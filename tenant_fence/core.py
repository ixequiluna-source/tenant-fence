"""Read-only authorization experiments against explicitly configured loopback targets."""

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit


class InvalidExperiment(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate(base, specification, environment):
    try:
        parsed = urlsplit(base)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise InvalidExperiment("Use a literal loopback IP and explicit port") from exc
    if (
        parsed.scheme != "http"
        or not address.is_loopback
        or not port
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise InvalidExperiment("Only explicit HTTP loopback origins are supported")
    if not isinstance(specification, dict) or set(specification) != {
        "tenants",
        "detail",
        "collection",
    }:
        raise InvalidExperiment("Manifest requires tenants, detail and collection")
    tenants = specification["tenants"]
    if not isinstance(tenants, list) or not 2 <= len(tenants) <= 8:
        raise InvalidExperiment("Configure two to eight synthetic tenants")
    for route in [specification["detail"], specification["collection"]]:
        if (
            not isinstance(route, str)
            or not re.fullmatch(r"/[A-Za-z0-9_/{\}-]{1,150}", route)
            or route.startswith("//")
            or ".." in route
        ):
            raise InvalidExperiment("Routes must be bounded relative paths")
    if (
        specification["detail"].count("{id}") != 1
        or any(c in specification["detail"].replace("{id}", "") for c in "{}")
        or any(c in specification["collection"] for c in "{}")
    ):
        raise InvalidExperiment("Detail route needs one id placeholder")
    tokens = []
    for tenant in tenants:
        if not isinstance(tenant, dict) or set(tenant) != {
            "id",
            "resource",
            "marker",
            "token_env",
        }:
            raise InvalidExperiment("Invalid tenant fields")
        for key in ["id", "resource", "token_env"]:
            if not isinstance(tenant[key], str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{1,64}", tenant[key]
            ):
                raise InvalidExperiment(
                    "IDs and environment names must be bounded labels"
                )
        marker = tenant["marker"]
        if not isinstance(marker, str) or not 12 <= len(marker) <= 128:
            raise InvalidExperiment("Each synthetic marker needs 12 to 128 characters")
        token = environment.get(tenant["token_env"], "")
        if (
            not isinstance(token, str)
            or not 12 <= len(token) <= 512
            or any(ord(c) < 33 or ord(c) > 126 for c in token)
        ):
            raise InvalidExperiment("Missing or invalid synthetic bearer token")
        tokens.append(token)
    for key in ["id", "resource", "marker", "token_env"]:
        if len({t[key] for t in tenants}) != len(tenants):
            raise InvalidExperiment("Tenant fields must be unique")
    if len(set(tokens)) != len(tokens):
        raise InvalidExperiment("Tenants require distinct bearer tokens")
    return base.rstrip("/"), tenants, tokens


def request(base, path, token=None, tenant_hint=None, timeout=2):
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if tenant_hint:
        headers["X-Tenant-ID"] = tenant_hint
    req = urllib.request.Request(base + path, headers=headers, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        try:
            response = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                return None, None
            content = raw.decode("utf-8")
            # Search decoded strings too; escaped JSON must not hide a synthetic marker.
            try:
                decoded = json.dumps(json.loads(content), ensure_ascii=False)
            except (json.JSONDecodeError, RecursionError):
                decoded = ""
            return response.status, content + "\n" + decoded
    except (OSError, urllib.error.URLError, UnicodeError, ValueError):
        return None, None


def evaluate(base, specification, environment=None):
    base, tenants, tokens = validate(
        base, specification, os.environ if environment is None else environment
    )
    results = []

    def check(kind, expected, status, body, own, forbidden):
        leaked = body is not None and any(marker in body for marker in forbidden)
        if leaked:
            verdict, reason = (
                "FAIL",
                "Foreign synthetic marker appeared in the response.",
            )
        elif status is None or status >= 500 or 300 <= status < 400:
            verdict, reason = (
                "INCONCLUSIVE",
                "Transport, redirect or service failure prevents a conclusion.",
            )
        elif expected == "deny":
            verdict = "PASS" if status in (401, 403, 404) else "FAIL"
            reason = (
                "Access denied without foreign markers."
                if verdict == "PASS"
                else "Configured private access was not denied."
            )
        elif 200 <= status < 300 and own in (body or ""):
            verdict, reason = (
                "PASS",
                "Own synthetic record is observable without foreign markers.",
            )
        else:
            verdict, reason = (
                "INCONCLUSIVE",
                "Positive control did not expose the expected own record.",
            )
        results.append(
            {
                "check": len(results) + 1,
                "kind": kind,
                "status": status,
                "verdict": verdict,
                "reason": reason,
            }
        )

    # Repeated identities exercise cache contamination as well as object-ID checks.
    for i, tenant in enumerate(tenants):
        own = tenant["marker"]
        foreign = [t["marker"] for j, t in enumerate(tenants) if j != i]
        path = specification["detail"].replace(
            "{id}", quote(tenant["resource"], safe="")
        )
        check(
            "own-record control", "allow", *request(base, path, tokens[i]), own, foreign
        )
        check("anonymous detail", "deny", *request(base, path), own, [own] + foreign)
        check(
            "own collection control",
            "allow",
            *request(base, specification["collection"], tokens[i]),
            own,
            foreign,
        )
        for j, other in enumerate(tenants):
            if i == j:
                continue
            other_path = specification["detail"].replace(
                "{id}", quote(other["resource"], safe="")
            )
            check(
                "foreign record",
                "deny",
                *request(base, other_path, tokens[i]),
                own,
                [other["marker"]],
            )
            check(
                "forged tenant header",
                "deny",
                *request(base, other_path, tokens[i], other["id"]),
                own,
                [other["marker"]],
            )
            check(
                "forged collection header",
                "allow",
                *request(base, specification["collection"], tokens[i], other["id"]),
                own,
                foreign,
            )
    verdict = (
        "FAIL"
        if any(r["verdict"] == "FAIL" for r in results)
        else "INCONCLUSIVE"
        if any(r["verdict"] == "INCONCLUSIVE" for r in results)
        else "PASS"
    )
    return {
        "experiment": "tenant boundary matrix",
        "verdict": verdict,
        "summary": {
            "FAIL": "At least one configured boundary was violated.",
            "INCONCLUSIVE": "Positive controls or transport did not support a complete conclusion.",
            "PASS": "Configured own-record controls and cross-tenant denials passed.",
        }[verdict],
        "checks": results,
        "scope": "Read-only detail and collection routes; synthetic loopback targets only. Not a complete authorization audit.",
    }
