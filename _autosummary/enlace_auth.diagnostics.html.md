# enlace_auth.diagnostics

Auth-specific doctor checks that plug into `enlace.doctor.run_doctor`.

Usage:

```default
from enlace.doctor import run_doctor
from enlace_auth.diagnostics import static_checks, http_checks

report = run_doctor(
    config,
    base_url="http://localhost:8000",
    extra_static_checks=static_checks,
    extra_http_checks=http_checks,
)
```

These checks were previously hard-wired into `enlace.doctor` itself; they
moved here when auth was extracted from enlace.

### Functions

| [`check_connector_session_longevity`](#enlace_auth.diagnostics.check_connector_session_longevity)(config)   | Can a connector survive its own access-token expiry unattended?     |
|----------------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| [`check_csrf`](#enlace_auth.diagnostics.check_csrf)(config, base_url, timeout)       | GET /auth/csrf must return JSON with a 'csrf' key.                  |
| `check_oauth_importable`(config)                                                             |                                                                     |
| [`check_oauth_server_advertises_refresh`](#enlace_auth.diagnostics.check_oauth_server_advertises_refresh)(...)  | The live server must offer refresh_token in its discovery metadata. |
| `check_shared_passwords`(config)                                                             |                                                                     |
| `check_signing_key`(config)                                                                  |                                                                     |

### enlace_auth.diagnostics.check_connector_session_longevity(config)

Can a connector survive its own access-token expiry unattended?

THE check for the failure this exists to prevent: an authorization server
that issues short access tokens and no refresh token strands every MCP
connector the moment the first token expires. Nothing errors — the connector
process stays healthy and the endpoint keeps answering — it just returns 401
forever until a human re-runs the browser authorization. In production that
read as “the connector has been down all day” and took a user complaint to
surface, because expiry is logged at INFO on the connector, not here.

* **Return type:**
  [`Iterable`](https://docs.python.org/3/library/typing.html#typing.Iterable)[`Check`]

### enlace_auth.diagnostics.check_csrf(config, base_url, timeout)

GET /auth/csrf must return JSON with a ‘csrf’ key.

This is THE check that catches the i2mint/enlace#11 regression: when auth
is silently disabled, the SPA catch-all returns `<!doctype html>`
instead of JSON.

* **Return type:**
  [`Iterable`](https://docs.python.org/3/library/typing.html#typing.Iterable)[`Check`]

### enlace_auth.diagnostics.check_oauth_server_advertises_refresh(config, base_url, timeout)

The live server must offer refresh_token in its discovery metadata.

Static config can be right while the deployed build is an older release that
has no refresh support at all — exactly the drift that caused the outage
(config and code were fine locally; the installed wheel was what served
requests). This asks the running server what it actually advertises.

* **Return type:**
  [`Iterable`](https://docs.python.org/3/library/typing.html#typing.Iterable)[`Check`]
