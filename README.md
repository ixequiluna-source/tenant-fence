![tenant-fence — A tenant ID is not authorization.](assets/cover.svg)

# tenant-fence

**Prove that one organization cannot read another organization's records. Then prove the test can catch a broken boundary.**

A Python authorization-testing lab that sends real HTTP requests to synthetic loopback services. It exercises own-record controls, foreign object IDs, anonymous access, forged tenant headers and collection responses. Reports preserve verdicts without copying bearer tokens or response bodies.

[![Experiments](https://github.com/ixequiluna-source/tenant-fence/actions/workflows/verify.yml/badge.svg)](https://github.com/ixequiluna-source/tenant-fence/actions/workflows/verify.yml)
[Español](README.es.md) · [Design and scope](docs/DESIGN.md) · [Example report](docs/example-report.html) · [Author](https://ixequiluna.ai)

## Run the lab

Requires Python 3.11+, no runtime dependencies:

```sh
git clone https://github.com/ixequiluna-source/tenant-fence.git
cd tenant-fence
python -m tenant_fence demo --out artifacts
```

Open `artifacts/report.html`. The demo starts temporary local HTTP servers, executes the matrix and shuts them down. No database, cloud account or Vercel plan is required.

| Fixture | Expected result | Failure reproduced |
| --- | --- | --- |
| Broken object authorization | **FAIL** | Changing an object ID exposes another tenant's marker. |
| Trusted client tenant header | **FAIL** | A client-controlled header overrides the authenticated tenant. |
| Leaky collection | **FAIL** | A list includes another tenant's records. |
| Scoped implementation | **PASS** | Own records work and configured foreign reads are denied. |
| Deny everything | **INCONCLUSIVE** | The positive controls fail, so denials prove little. |

A successful demo exit means the experiments produced these expected outcomes. It does **not** mean the intentionally vulnerable fixtures are safe.

## Check your local synthetic fixture

`examples/manifest.json` describes two tenants, their public synthetic resource IDs, distinctive markers, environment-variable names and two read-only routes. Supply distinct tokens through the named environment variables, then run:

```sh
python -m tenant_fence check --base-url http://127.0.0.1:8000 --manifest examples/manifest.json --out artifacts
```

The service must already be running and contain those synthetic records. `check` does not create records or alter a database. The shipped demo requires no setup and provides a complete reference adapter in `tenant_fence/demo.py`.

Exit codes: **0** PASS, **1** boundary violation, **2** inconclusive/invalid experiment. Positive controls, network failures, redirects and 5xx responses cannot silently become a pass. A 403 response that still includes a foreign marker is a failure.

Optional installation: `python -m pip install .`, then `tenant-fence demo`.

## Deliberate perimeter

- Only literal loopback HTTP origins with an explicit port. Hostnames, public/private-network targets, userinfo, URL queries and origin paths are rejected.
- GET requests only. No mutations, cloud credentials or live customer data.
- Redirects are not followed; system HTTP proxies are disabled for the experiment.
- Response reads are capped at 1 MiB and socket operations have a two-second timeout.
- Two to eight distinct synthetic identities. The matrix has 12 checks with the supplied two-tenant configuration.
- Reused detail paths across identities exercise cache isolation; tests include a cache that incorrectly shares responses across tenants.

## Scope is part of the result

PASS applies to the configured detail and collection reads, identities and markers. It does not prove all API routes, write authorization, roles, database row-level security, files, WebSockets, timing channels or production isolation. The fixture bearer tokens are synthetic constants, not an authentication implementation to deploy.

## Tests

```sh
python -m pip install .
python -m unittest discover -s tests -v
python tools/check_demo.py
```

Integration tests include broken object checks, forged tenant headers, list leakage, leakage inside a denial body, cache contamination, blanket denial, service outage and redirects. CLI and report tests verify failure exits and absence of tokens/markers in generated evidence.

## Background

[OWASP's API1:2023 guidance](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) describes object-level authorization failures. This project supplies a small reproducible experiment around that class of failure; it is not an OWASP certification or endorsement.

Built and maintained by **[Dr. Ixequi Luna](https://ixequiluna.ai)**. MIT licensed; retain the copyright and license notice when reusing the code.
