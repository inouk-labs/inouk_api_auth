# Inouk API Auth

> **This repository is maintained on GitLab:** <https://gitlab.com/cmorisse/inouk_api_auth>
>
> <https://github.com/inouk-labs/inouk_api_auth> is a read-only mirror, updated from GitLab on
> every push to a release branch. A commit pushed to GitHub is overwritten by the next update:
> open issues and merge requests on GitLab.

Token-based API authentication system with plain JSON support for Odoo.

**License**: Elastic License v2.0 — see [`LICENSE`](LICENSE) for the full text.

> Source-available, perpetual. Commercial use requires a paid subscription.
> Third parties may not provide `inouk_api_auth` to others as a hosted or
> managed service without a separate commercial agreement.
> Migrated from LGPL-3 on 2026-05-13.

## Features

- **Multiple authentication methods**: Bearer tokens, AWS Signature V4, HTTP Basic Auth
- **Plain JSON support**: Bypass Odoo's JSON-RPC for external REST clients
- **HTTPS integrity enforcement**: Automatic token compromise detection
- **Token lifecycle management**: Expiration, compromise detection, and security logging
- **Comprehensive request analysis**: Real IP detection, proxy chain analysis

## Authentication Methods

### Bearer Token (`auth='ik_bearer'`)
Standard Bearer token authentication supporting:
- `Authorization: Bearer <token>` header
- `X-Gitlab-Token: <token>` header (GitLab webhook compatibility)
- `?access_token=<token>` URL parameter (fallback)

### AWS Signature V4 (`auth='ik_awssigv4'`)
Full AWS SigV4 implementation for AWS CLI/SDK compatibility:
- Credential-based authentication with access key and secret
- Request signing validation with timestamp and region
- Compatible with AWS tools and libraries

### HTTP Basic Auth (`auth='ik_httpbasicauth'`)
RFC 7617 compliant Basic authentication:
- `Authorization: Basic <base64(username:password)>` header
- Secure password hashing with verification
- Username-based token lookup

## OAuth 2.0 / 2.1 Authentication

This module supports three OAuth flows for different use cases:

| Flow | Use Case | User Interaction | RFC |
|------|----------|-----------------|-----|
| **Client Credentials** | Server-to-server, scripts, CI/CD | None (M2M) | OAuth 2.0 |
| **Authorization Code + PKCE** | Claude.ai, web apps | Yes (consent screen) | OAuth 2.1 |
| **Device Code** | CLI tools (mpy/mgx) in remote environments | Yes (browser) | RFC 8628 |

### Discovery Endpoints

Clients can discover OAuth endpoints automatically:

**Authorization Server Metadata (RFC 8414):**
```bash
curl https://your-server/.well-known/oauth-authorization-server
```

**Response:**
```json
{
  "issuer": "https://your-server",
  "authorization_endpoint": "https://your-server/oauth/authorize",
  "token_endpoint": "https://your-server/oauth/token",
  "registration_endpoint": "https://your-server/oauth/register",
  "device_authorization_endpoint": "https://your-server/oauth/device/code",
  "response_types_supported": ["code"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["mcp:discovery", "mcp:metadata", "mcp:operations", "..."]
}
```

**Protected Resource Metadata (RFC 9728):**
```bash
curl https://your-server/.well-known/oauth-protected-resource
```

**Response:**
```json
{
  "resource": "https://your-server/mcp",
  "authorization_servers": ["https://your-server"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["mcp:discovery", "mcp:metadata", "mcp:operations"]
}
```

### OAuth 2.0 Client Credentials (Machine-to-Machine)

For server-to-server communication without user interaction.

**Prerequisites:**
1. Create an OAuth Client in Odoo (Settings > Technical > OAuth Client Registration)
2. Enable `client_credentials` grant type
3. Generate a client secret

**Step 1: Request Access Token**
```bash
curl -X POST https://your-server/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=ikac_YOUR_CLIENT_ID" \
  -d "client_secret=ikacs_YOUR_CLIENT_SECRET" \
  -d "scope=mcp:discovery mcp:metadata mcp:operations"
```

**Response:**
```json
{
  "access_token": "ikaa_eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "mcp:discovery mcp:metadata mcp:operations"
}
```

**Step 2: Use the Token**
```bash
curl https://your-server/mcp \
  -H "Authorization: Bearer ikaa_eyJhbGciOiJIUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tools/list", "id": 1}'
```

### OAuth 2.1 Authorization Code + PKCE (User Authentication)

For web applications and Claude.ai integration. PKCE (RFC 7636) is **mandatory**.

```
┌─────────────┐                                    ┌─────────────────┐
│   Client    │                                    │  Muppy Server   │
│ (Claude.ai) │                                    │                 │
└──────┬──────┘                                    └────────┬────────┘
       │                                                    │
       │ 1. Generate code_verifier + code_challenge         │
       │                                                    │
       │ 2. Redirect user → /oauth/authorize                │
       │    ?response_type=code                             │
       │    &client_id=...                                  │
       │    &code_challenge=...                             │
       │    &code_challenge_method=S256                     │
       │───────────────────────────────────────────────────>│
       │                                                    │
       │         ┌──────────────────────────────────┐       │
       │         │  User sees consent screen        │       │
       │         │  and clicks [Authorize]          │       │
       │         └──────────────────────────────────┘       │
       │                                                    │
       │ 3. Redirect back with ?code=AUTH_CODE              │
       │<───────────────────────────────────────────────────│
       │                                                    │
       │ 4. POST /oauth/token                               │
       │    code=AUTH_CODE                                  │
       │    code_verifier=ORIGINAL_VERIFIER                 │
       │───────────────────────────────────────────────────>│
       │                                                    │
       │ 5. { access_token, refresh_token }                 │
       │<───────────────────────────────────────────────────│
```

**Step 1: Generate PKCE Code Verifier and Challenge**

```python
import secrets
import hashlib
import base64

# Generate code_verifier (43-128 characters)
code_verifier = secrets.token_urlsafe(32)
# Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

# Generate code_challenge = BASE64URL(SHA256(code_verifier))
digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
# Example: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

Or with bash:
```bash
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=' | tr '/+' '_-')
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=' | tr '/+' '_-')
```

**Step 2: Redirect User to Authorization Endpoint**

Build the authorization URL:
```
https://your-server/oauth/authorize
  ?response_type=code
  &client_id=ikac_YOUR_CLIENT_ID
  &redirect_uri=https://your-app/callback
  &scope=mcp:discovery mcp:metadata mcp:operations
  &state=RANDOM_STATE_FOR_CSRF
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
```

The user sees a consent screen and clicks "Authorize".

**Step 3: Handle Callback with Authorization Code**

After consent, the user is redirected to:
```
https://your-app/callback?code=AUTH_CODE_123&state=RANDOM_STATE_FOR_CSRF
```

**Step 4: Exchange Code for Tokens**
```bash
curl -X POST https://your-server/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_123" \
  -d "redirect_uri=https://your-app/callback" \
  -d "client_id=ikac_YOUR_CLIENT_ID" \
  -d "code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

**Response:**
```json
{
  "access_token": "ikaa_yyy...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ikrt_zzz...",
  "scope": "mcp:discovery mcp:metadata mcp:operations"
}
```

### Device Code Flow (CLI Tools)

For CLI applications (mpy/mgx) in remote environments (SSH, containers) where the browser is not on the same machine.

> **Tutorial:** for a step-by-step walkthrough that explains the **why** behind each step (when to choose Device Code vs other flows, what each token does, why refresh tokens rotate), see [docs/ikaa_cli_authentication_tutorial.md](docs/ikaa_cli_authentication_tutorial.md). The reference below is endpoint-by-endpoint.

```
┌─────────────┐              ┌─────────────┐              ┌─────────────────┐
│   CLI mpy   │              │  Browser    │              │  Muppy Server   │
└──────┬──────┘              └──────┬──────┘              └────────┬────────┘
       │                            │                              │
       │ 1. POST /oauth/device/code                                │
       │──────────────────────────────────────────────────────────>│
       │                                                           │
       │ 2. { device_code, verification_uri_complete }             │
       │<──────────────────────────────────────────────────────────│
       │                                                           │
       │ 3. Display URL to user                                    │
       │    "Visit: https://.../oauth/device?code=dc_xxx"          │
       │                                                           │
       │         ┌───────────────────────────────────────────┐     │
       │         │ User opens URL in browser                 │     │
       │         │ (same machine, phone, or other device)    │     │
       │         └───────────────────────────────────────────┘     │
       │                        │                                  │
       │                        │ 4. GET /oauth/device?code=dc_xxx │
       │                        │─────────────────────────────────>│
       │                        │                                  │
       │                        │ 5. Login + Consent screen        │
       │                        │<─────────────────────────────────│
       │                        │                                  │
       │                        │ 6. [Authorize]                   │
       │                        │─────────────────────────────────>│
       │                                                           │
       │ 7. Poll: POST /oauth/token (grant_type=device_code)       │
       │──────────────────────────────────────────────────────────>│
       │                                                           │
       │ 8. { access_token, refresh_token }                        │
       │<──────────────────────────────────────────────────────────│
```

**Step 1: Request Device Code**
```bash
curl -X POST https://your-server/oauth/device/code \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=mpy-cli" \
  -d "scope=mcp:discovery mcp:metadata mcp:operations"
```

**Response:**
```json
{
  "device_code": "dc_GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://your-server/oauth/device",
  "verification_uri_complete": "https://your-server/oauth/device?code=dc_GmRhmh...",
  "expires_in": 900,
  "interval": 5
}
```

**Step 2: Display URL to User**

The CLI displays:
```
To sign in, visit:
  https://your-server/oauth/device?code=dc_GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS

Waiting for authorization...
```

**Step 3: User Opens URL and Authorizes**

The user opens the URL (on any device), logs in to Odoo if needed, and sees a consent screen.

**Step 4: CLI Polls for Token**
```bash
# Poll every 5 seconds until authorized
curl -X POST https://your-server/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=dc_GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS" \
  -d "client_id=mpy-cli"
```

**Polling Responses:**

While waiting:
```json
{"error": "authorization_pending"}
```

If polling too fast:
```json
{"error": "slow_down"}
```

When user denies:
```json
{"error": "access_denied"}
```

When authorized:
```json
{
  "access_token": "ikaa_yyy...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ikrt_zzz...",
  "scope": "mcp:discovery mcp:metadata mcp:operations"
}
```

**Python Example (Polling Loop):**
```python
import time
import requests

def poll_for_token(server_url, device_code, client_id, interval=5, timeout=900):
    """Poll until user authorizes or timeout."""
    deadline = time.time() + timeout

    while time.time() < deadline:
        resp = requests.post(
            f"{server_url}/oauth/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": client_id,
            }
        )
        result = resp.json()

        if "access_token" in result:
            return result  # Success!

        error = result.get("error")
        if error == "authorization_pending":
            time.sleep(interval)
            continue
        elif error == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        else:
            raise Exception(f"Authorization failed: {error}")

    raise Exception("Authorization timed out")
```

### Dynamic Client Registration (RFC 7591)

Clients can register themselves automatically:

```bash
curl -X POST https://your-server/oauth/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": ["https://my-app.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none"
  }'
```

**Response:**
```json
{
  "client_id": "ikac_abc123...",
  "client_name": "My Application",
  "redirect_uris": ["https://my-app.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "client_id_issued_at": 1704067200,
  "client_secret_expires_at": 0
}
```

**Allowed redirect URI patterns** (configurable):
- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- `http://localhost:*/callback` (for local development)
- `http://127.0.0.1:*/callback`

### Scopes

MCP (Model Context Protocol) scopes control access to Odoo resources:

| Scope | Description |
|-------|-------------|
| `mcp:discovery` | List domains, models, fields, and methods |
| `mcp:source` | Read Python method source code |
| `mcp:read` | Search and read record data |
| `mcp:write` | Create, modify, and delete records |
| `mcp:execute` | Execute whitelisted methods |

Request scopes in the authorization request:
```
scope=mcp:discovery mcp:read mcp:write mcp:execute
```

### Token Refresh

Use refresh tokens to obtain new access tokens without user interaction:

```bash
curl -X POST https://your-server/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=ikrt_zzz..." \
  -d "client_id=ikac_YOUR_CLIENT_ID"
```

**Response:**
```json
{
  "access_token": "ikaa_new_token...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "ikrt_new_refresh_token...",
  "scope": "mcp:discovery mcp:metadata mcp:operations"
}
```

**Token Rotation**: When `inouk_api_auth.oauth_rotate_refresh_tokens` is enabled, each refresh request returns a new refresh token. The old refresh token is invalidated.

**Token Lifetimes** (configurable via system parameters):
- Access tokens: 1 hour (default)
- Refresh tokens: 30 days (default)
- Authorization codes: 10 minutes

## Plain JSON Support

### Why This Feature Exists

External REST clients (LEGO, Terraform, curl, etc.) expect standard JSON APIs:
- **Send**: `{"key": "value"}`
- **Receive**: `{"result": "data"}`

Odoo's `type='json'` routes expect JSON-RPC protocol with wrapper:
- **Expected**: `{"jsonrpc": "2.0", "method": "call", "params": {...}, "id": 1}`
- **Returns**: `{"jsonrpc": "2.0", "result": {...}, "id": 1}`

This incompatibility prevents integration with external tools.

### Usage

Add `ik_plain_json=True` to any JSON route:

```python
from odoo import http

class MyController(http.Controller):

    @http.route('/api/endpoint', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, ik_plain_json=True)
    def my_api(self, **params):
        # params contains the raw JSON body
        return {"status": "success", "data": params}
```

**Client usage:**
```bash
curl -X POST https://example.com/api/endpoint \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{"key": "value"}'
```

**Response:**
```json
{"status": "success", "data": {"key": "value"}}
```

### Implementation Details

The module patches `JsonRequest` to detect `ik_plain_json` routes and:

1. **Parameter handling**: Use raw JSON body as controller params (no JSON-RPC parsing)
2. **Response formatting**: Return plain JSON responses (no JSON-RPC wrapper)
3. **Error handling**: Standard JSON error responses with appropriate HTTP status codes

**Error response format:**
```json
{"error": "Error message", "status": "error"}
```

### Managing HTTP Status Codes

With `ik_plain_json=True`, you can control HTTP response status codes by raising exceptions.

#### Using Werkzeug HTTPException (Recommended)

```python
from werkzeug.exceptions import BadRequest, NotFound, Forbidden, Conflict

@http.route('/api/resource', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def create_resource(self, name, **params):
    if not name:
        raise BadRequest("Name is required")  # Returns HTTP 400

    existing = self.env['my.model'].search([('name', '=', name)])
    if existing:
        raise Conflict("Resource already exists")  # Returns HTTP 409

    return {'status': 'success', 'id': new_record.id}
```

#### Common HTTPException Classes

| Exception | HTTP Status | Use Case |
|-----------|-------------|----------|
| `BadRequest` | 400 | Invalid input, missing required fields |
| `Unauthorized` | 401 | Authentication failed |
| `Forbidden` | 403 | Insufficient permissions |
| `NotFound` | 404 | Resource not found |
| `Conflict` | 409 | Resource already exists, version conflict |
| `UnprocessableEntity` | 422 | Validation errors |
| `InternalServerError` | 500 | Unexpected server errors |

#### Using Custom Exceptions with status_code

For custom status codes, create an exception class with a `status_code` attribute:

```python
class QuotaExceeded(Exception):
    status_code = 429

    def __init__(self, message="Quota exceeded"):
        self.name = message
        super().__init__(message)

@http.route('/api/resource', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def create_resource(self, **params):
    if self._quota_exceeded():
        raise QuotaExceeded("Daily quota exceeded, try again tomorrow")
    # ... rest of logic
```

#### Status Code Resolution Order

| Exception Type | Status Code Source |
|----------------|-------------------|
| `werkzeug.exceptions.HTTPException` | `e.code` |
| Exception with `status_code` attribute | `e.status_code` |
| Any other exception | `500` (default) |

### Why Monkey Patching is Necessary

**Technical constraints:**
- Odoo's request factory instantiates `JsonRequest` internally based on `Content-Type` headers
- External clients cannot be modified to send custom headers
- No exposed factory method to override request class instantiation

**Alternative approaches considered:**
- **Classic inheritance**: Cannot replace Odoo's internal request factory
- **Middleware**: Would require WSGI stack modifications
- **Decorator pattern**: Cannot intercept request parsing early enough

**Our solution** is the least invasive approach that maintains full Odoo compatibility while enabling external tool integration.

## Token Management

### Security Features

- **HTTPS enforcement**: Tokens sent over HTTP are automatically compromised
- **Real IP detection**: Supports Cloudflare and other proxy configurations
- **Compromise detection**: Automatic token invalidation on security violations
- **Audit logging**: Complete request tracing with IP and proxy information

### Token Types

Tokens support different authentication backends:
- `bearer`: Standard Bearer tokens
- `xgitlabtoken`: GitLab webhook tokens
- `awssigv4`: AWS access key credentials
- `httpbasicauth`: HTTP Basic Auth credentials

### Request Context

All authentication methods populate `request.inouk_api_auth` with:

```python
{
    'token': token_object,
    'token_name': 'Token Name',
    'token_type': 'bearer|awssigv4|httpbasicauth',
    'user': user_object,
    'is_compromised': False,
    'is_expired': False,
    'authenticated_at': '2025-01-01T12:00:00',
    'auth_details': {
        # Method-specific authentication details
    },
    'request_source': {
        'remote_ip': '1.2.3.4',  # Real client IP
        'via': '5.6.7.8',        # Proxy IP (if behind proxy)
        'proxy_chain': ['5.6.7.8'],
        'proxy_type': 'cloudflare|nginx|generic',
        'using_https': True,
        'user_agent': 'curl/8.0.0',
        'referer': 'https://example.com'
    }
}
```

## Integration Examples

### ACME DNS Challenge (LEGO)
```python
@http.route('/dns/challenge', type='json', auth='ik_httpbasicauth',
            methods=['POST'], csrf=False, ik_plain_json=True)
def dns_challenge(self, domain, token, **params):
    # LEGO sends: {"domain": "example.com", "token": "challenge_token"}
    return {"message": "Challenge added successfully"}
```

### Webhook Endpoints
```python
@http.route('/webhooks/deploy', type='json', auth='ik_bearer',
            methods=['POST'], csrf=False, ik_plain_json=True)
def deploy_webhook(self, repository, commit, **params):
    # GitHub/GitLab webhook payload directly available in params
    return {"status": "deployment_started"}
```

### Infrastructure APIs
```python
@http.route('/infra/provision', type='json', auth='ik_awssigv4',
            methods=['POST'], csrf=False, ik_plain_json=True)
def provision_infrastructure(self, **params):
    # AWS CLI/SDK compatible endpoint
    return {"instance_id": "i-1234567890abcdef0"}
```

## Testing Plain JSON Support

### Running Automated Tests

Run the full test suite for `inouk_api_auth`:
```bash
bin/start_odoo --test-enable --stop-after-init -u inouk_api_auth
```

Run only the plain JSON tests (using test tag):
```bash
bin/start_odoo --test-enable --stop-after-init -u inouk_api_auth --test-tags=plain_json
```

### Test Endpoints

The module includes test endpoints for validating `ik_plain_json` functionality:

| Endpoint | Purpose |
|----------|---------|
| `/inouk/api_auth/test/plain_json/echo` | Echo params - validates request/response |
| `/inouk/api_auth/test/plain_json/error_400` | Test BadRequest (HTTP 400) |
| `/inouk/api_auth/test/plain_json/error_403` | Test Forbidden (HTTP 403) |
| `/inouk/api_auth/test/plain_json/error_404` | Test NotFound (HTTP 404) |
| `/inouk/api_auth/test/plain_json/error_custom` | Test custom status_code (HTTP 422) |
| `/inouk/api_auth/test/plain_json/error_500` | Test generic exception (HTTP 500) |
| `/inouk/api_auth/test/plain_json/datetime` | Test datetime serialization |
| `/inouk/api_auth/test/plain_json/response_object` | Test Response pass-through |

### Manual Testing with curl

1. **Create a test token** in Odoo (Settings > Technical > API Auth Tokens)

2. **Test basic echo endpoint:**
```bash
curl -X POST https://your-server/inouk/api_auth/test/plain_json/echo \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "hello", "count": 42}'
```

**Expected response** (plain JSON, no JSON-RPC wrapper):
```json
{"status": "success", "echo": {"message": "hello", "count": 42}}
```

3. **Test error handling (400 Bad Request):**
```bash
curl -i -X POST https://your-server/inouk/api_auth/test/plain_json/error_400 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 400 with plain JSON error:
```json
{"error": "400 Bad Request: Test bad request error", "status": "error"}
```

4. **Test custom status code (422):**
```bash
curl -i -X POST https://your-server/inouk/api_auth/test/plain_json/error_custom \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** HTTP 422 with plain JSON error:
```json
{"error": "Test custom status code error", "status": "error"}
```

5. **Test datetime serialization:**
```bash
curl -X POST https://your-server/inouk/api_auth/test/plain_json/datetime \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:** ISO-formatted datetime strings:
```json
{"datetime": "2025-01-15T10:30:00", "date": "2025-01-15", "string": "test", "number": 42}
```

### Validation Checklist

When testing `ik_plain_json` support, verify:

- [ ] Successful responses return plain JSON (no `jsonrpc`, `id`, `result` wrapper keys)
- [ ] Error responses return plain JSON with `{"error": "...", "status": "error"}` format
- [ ] HTTPException classes return correct HTTP status codes (400, 403, 404, etc.)
- [ ] Custom exceptions with `status_code` attribute return that status code
- [ ] Generic exceptions return HTTP 500
- [ ] Datetime objects are serialized to ISO format strings
- [ ] Response objects from endpoints are passed through unchanged
- [ ] Content-Type header is `application/json`

This module enables seamless integration between Odoo and external tools while maintaining security and auditability.