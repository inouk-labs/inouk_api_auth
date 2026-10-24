# -*- coding: utf-8 -*-
"""OAuth 2.0/2.1 Authorization Server

This controller implements OAuth 2.0/2.1 flows (RFC 6749, OAuth 2.1) for API
authentication. Supports discovery via RFC 8414 (Authorization Server Metadata).

Flows supported:
- client_credentials: Machine-to-machine (API keys, CI/CD)
- authorization_code: User-interactive (web apps, CLI) - OAuth 2.1 with PKCE
- refresh_token: Token renewal
- device_code: CLI in remote environments (RFC 8628)

See auth.py header for detailed documentation on route type selection.
"""

import json
import logging
import secrets
from urllib.parse import urlencode

from odoo import http, fields
from odoo.http import request, Response
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class OAuthController(http.Controller):

    # ═══════════════════════════════════════════════════════════════════════════
    # DISCOVERY ENDPOINTS (RFC 8414)
    # ═══════════════════════════════════════════════════════════════════════════

    @http.route('/.well-known/oauth-authorization-server', type='http', auth='none',
                methods=['GET'], csrf=False, save_session=False)
    def oauth_discovery(self, **kwargs):
        """OAuth 2.0 Authorization Server Metadata (RFC 8414).

        Returns metadata about the OAuth server so clients can discover endpoints.
        Extended for OAuth 2.1 Authorization Code + PKCE.
        """
        base_url = request.httprequest.host_url.rstrip('/')

        # Get supported scopes from config (default: empty for generic module)
        scopes_supported = self._get_scopes_supported()

        metadata = {
            'issuer': base_url,

            # Authorization endpoints
            'authorization_endpoint': f'{base_url}/oauth/authorize',
            'token_endpoint': f'{base_url}/oauth/token',
            'registration_endpoint': f'{base_url}/oauth/register',

            # Device Authorization (RFC 8628)
            'device_authorization_endpoint': f'{base_url}/oauth/device/code',

            # Supported response types
            'response_types_supported': ['code'],

            # Supported grant types (extended)
            'grant_types_supported': [
                'authorization_code',
                'refresh_token',
                'client_credentials',  # Backward compatibility
                'urn:ietf:params:oauth:grant-type:device_code',
            ],

            # PKCE (required for authorization_code)
            'code_challenge_methods_supported': ['S256'],

            # Token endpoint auth methods
            'token_endpoint_auth_methods_supported': [
                'none',
                'client_secret_post',
                'client_secret_basic',
            ],

            # Scopes (configurable)
            'scopes_supported': scopes_supported,

            # Resource indicators (RFC 8707)
            'resource_indicators_supported': True,

            # Refresh tokens
            'refresh_token_supported': True,

            # UI locales
            'ui_locales_supported': ['en', 'fr'],
        }

        _logger.debug("OAuth discovery request from %s", request.httprequest.remote_addr)

        return Response(
            json.dumps(metadata),
            content_type='application/json',
            headers={
                'Cache-Control': 'public, max-age=3600',
                'Access-Control-Allow-Origin': '*',
            },
            status=200
        )

    def _get_scopes_supported(self):
        """Get supported scopes for authorization server metadata.

        Resolution order:
        1. System parameter inouk_api_auth.oauth_scopes_supported (explicit override)
        2. Dynamic aggregation from active OAuth clients

        Returns:
            list: List of supported scope strings
        """
        ICP = request.env['ir.config_parameter'].sudo()
        scopes_str = ICP.get_param('inouk_api_auth.oauth_scopes_supported', '')
        if scopes_str:
            return [s.strip() for s in scopes_str.split(',') if s.strip()]

        try:
            return request.env['ik.oauth_client_registration']._get_all_scopes_supported()
        except Exception:
            return []

    # ═══════════════════════════════════════════════════════════════════════════
    # DYNAMIC CLIENT REGISTRATION (RFC 7591)
    # ═══════════════════════════════════════════════════════════════════════════

    @http.route('/oauth/register', type='http', auth='none', methods=['POST'],
                csrf=False, save_session=False)
    def oauth_register(self, **kwargs):
        """RFC 7591 - Dynamic Client Registration.

        Allows clients like Claude.ai to register themselves automatically.
        """
        # Parse request body
        content_type = request.httprequest.content_type or ''
        if 'application/json' not in content_type:
            return self._oauth_error('invalid_request', 'Content-Type must be application/json', 400)

        try:
            data = json.loads(request.httprequest.get_data(as_text=True))
        except json.JSONDecodeError:
            return self._oauth_error('invalid_request', 'Invalid JSON', 400)

        # Required fields
        client_name = data.get('client_name')
        redirect_uris = data.get('redirect_uris', [])

        if not client_name:
            return self._oauth_error('invalid_client_metadata', 'client_name is required', 400)

        # Normalize redirect_uris to list
        if isinstance(redirect_uris, str):
            redirect_uris = [redirect_uris]

        # Validate redirect URIs against allowed patterns
        allowed_patterns = self._get_allowed_redirect_patterns()
        for uri in redirect_uris:
            if not self._validate_redirect_uri_pattern(uri, allowed_patterns):
                return self._oauth_error(
                    'invalid_redirect_uri',
                    f"redirect_uri '{uri}' is not allowed",
                    400
                )

        # Create client registration
        ClientReg = request.env['ik.oauth_client_registration'].sudo()

        # Handle grant_types
        grant_types_input = data.get('grant_types', ['authorization_code', 'refresh_token'])
        if isinstance(grant_types_input, list):
            grant_types = ','.join(grant_types_input)
        else:
            grant_types = grant_types_input

        # ──────────────────────────────────────────────────────────────────────────
        # RFC 7591 Public Client Handling
        # ──────────────────────────────────────────────────────────────────────────
        # Some clients (e.g., Claude.ai) request 'client_secret_post' as their
        # preferred auth method but don't provide a client_secret. This is
        # technically a public client configuration.
        #
        # Per RFC 7591 Section 2, if no secret is provided, the client is a
        # public client and MUST use 'none' as token_endpoint_auth_method.
        # We auto-correct this to avoid breaking DCR for well-intentioned clients.
        # ──────────────────────────────────────────────────────────────────────────
        requested_auth_method = data.get('token_endpoint_auth_method', 'none')
        client_secret = data.get('client_secret')

        if requested_auth_method in ('client_secret_post', 'client_secret_basic') and not client_secret:
            # Client requested secret-based auth but provided no secret
            # → Treat as public client (PKCE will handle security)
            token_endpoint_auth_method = 'none'
            _logger.info(
                "OAuth DCR: Client '%s' requested '%s' without secret, auto-correcting to 'none' (public client)",
                client_name, requested_auth_method
            )
        else:
            token_endpoint_auth_method = requested_auth_method

        # Resolve scopes: use client-requested scope, or fall back to the
        # union of all MCP provider scopes if available.
        # TODO: remove MCP fallback when Claude.ai uses per-instance OAuth
        #   endpoints as advertised in authInfo (initialize response).
        #   Claude.ai currently ignores per-instance URLs and uses global
        #   /.well-known/oauth-authorization-server → /oauth/register →
        #   /oauth/authorize, bypassing the per-instance DCR that knows the
        #   provider vocabulary. ChatGPT handles this correctly.
        #   See: inouk_mcp/docs/claude_integration.md §"Known Issues"
        requested_scope = data.get('scope', '')
        if not requested_scope:
            try:
                McpProvider = request.env['ik.mcp_provider'].sudo()
                all_scopes = set()
                for provider in McpProvider.search([]):
                    all_scopes |= provider.get_scope_codes()
                if all_scopes:
                    requested_scope = ' '.join(sorted(all_scopes))
                    _logger.info(
                        "OAuth DCR: scope omitted, defaulting to MCP provider "
                        "scopes: %s", requested_scope,
                    )
            except KeyError:
                pass  # inouk_mcp not installed, no MCP scopes available

        client = ClientReg.create({
            'client_name': client_name,
            'redirect_uris': '\n'.join(redirect_uris) if redirect_uris else '',
            'registration_type': 'dynamic',
            'client_uri': data.get('client_uri'),
            'logo_uri': data.get('logo_uri'),
            'grant_types': grant_types,
            'response_types': 'code',
            'token_endpoint_auth_method': token_endpoint_auth_method,
            'allowed_scopes': requested_scope,
            'default_scopes': requested_scope,  # RFC 6749 §3.3: pre-defined default when scope omitted at authorize
        })

        # Generate secret if auth method requires it
        client_secret = None
        if client.token_endpoint_auth_method in ('client_secret_post', 'client_secret_basic'):
            client_secret = client.generate_client_secret()

        # Build response
        response_data = {
            'client_id': client.client_id,
            'client_name': client.client_name,
            'redirect_uris': redirect_uris,
            'grant_types': grant_types.replace(',', ' ').split(),
            'response_types': ['code'],
            'token_endpoint_auth_method': client.token_endpoint_auth_method,
            'client_id_issued_at': int(client.create_date.timestamp()),
            'client_secret_expires_at': 0,  # Never expires
        }

        if client_secret:
            response_data['client_secret'] = client_secret

        _logger.info("OAuth DCR: Registered client '%s' (id: %s)", client_name, client.client_id)

        return Response(
            json.dumps(response_data),
            status=201,
            content_type='application/json'
        )

    def _get_allowed_redirect_patterns(self):
        """Get allowed redirect URI patterns from config.

        Thin wrapper over ``ik.oauth_client_registration.get_global_redirect_patterns()``.
        Kept for HTTP controller backward compatibility — model classmethod is the
        canonical implementation.
        """
        return request.env['ik.oauth_client_registration'].get_global_redirect_patterns()

    def _validate_redirect_uri_pattern(self, uri, patterns):
        """Check if URI matches any allowed pattern.

        Thin wrapper over ``ik.oauth_client_registration.match_redirect_uri_pattern()``.
        Kept for HTTP controller backward compatibility — model classmethod is the
        canonical implementation.
        """
        return request.env['ik.oauth_client_registration'].match_redirect_uri_pattern(uri, patterns)

    # ═══════════════════════════════════════════════════════════════════════════
    # AUTHORIZATION ENDPOINT (OAuth 2.1)
    # ═══════════════════════════════════════════════════════════════════════════

    @http.route('/oauth/authorize', type='http', auth='user', methods=['GET', 'POST'],
                csrf=False)
    def oauth_authorize(self, **kwargs):
        """OAuth 2.1 Authorization Endpoint.

        GET: Display consent screen
        POST: Process consent decision

        Requires Odoo session (user must be logged in).
        """
        # Extract parameters
        response_type = kwargs.get('response_type')
        client_id = kwargs.get('client_id')
        redirect_uri = kwargs.get('redirect_uri')
        scope = kwargs.get('scope', '')
        state = kwargs.get('state')
        code_challenge = kwargs.get('code_challenge')
        code_challenge_method = kwargs.get('code_challenge_method')
        resource = kwargs.get('resource')

        # DEBUG: Log redirect_uri on both GET and POST
        _logger.info("OAuth authorize %s: redirect_uri = '%s'",
                    request.httprequest.method, redirect_uri)

        # ═══════════════════════════════════════════════════════════════════════
        # VALIDATION
        # ═══════════════════════════════════════════════════════════════════════

        # Validate required parameters
        if response_type != 'code':
            if redirect_uri:
                return self._oauth_error_redirect(
                    redirect_uri, state, 'unsupported_response_type',
                    "Only 'code' response_type is supported"
                )
            return self._oauth_error('unsupported_response_type',
                                     "Only 'code' response_type is supported", 400)

        if not client_id:
            return self._oauth_error('invalid_request', 'client_id is required', 400)

        if not redirect_uri:
            return self._oauth_error('invalid_request', 'redirect_uri is required', 400)

        # PKCE is REQUIRED for authorization_code flow
        if not code_challenge or code_challenge_method != 'S256':
            return self._oauth_error_redirect(
                redirect_uri, state, 'invalid_request',
                "PKCE with S256 is required"
            )

        # Lookup client
        ClientReg = request.env['ik.oauth_client_registration'].sudo()
        client = ClientReg.search([('client_id', '=', client_id), ('active', '=', True)], limit=1)

        if not client:
            return self._oauth_error('invalid_client', 'Client not found', 400)

        # Validate redirect_uri
        try:
            client.validate_redirect_uri(redirect_uri)
        except ValidationError as e:
            return self._oauth_error('invalid_redirect_uri', str(e), 400)

        # Validate and filter scopes
        validated_scope = client.validate_scope(scope)

        # ═══════════════════════════════════════════════════════════════════════
        # CONSENT HANDLING
        # ═══════════════════════════════════════════════════════════════════════

        if request.httprequest.method == 'POST':
            # User submitted consent form
            decision = kwargs.get('decision')

            if decision == 'deny':
                return self._oauth_error_redirect(
                    redirect_uri, state, 'access_denied',
                    "User denied the authorization request"
                )

            # Create authorization code
            AuthCode = request.env['ik.oauth_authorization_code'].sudo()
            auth_code = AuthCode.create({
                'client_registration_id': client.id,
                'user_id': request.env.user.id,
                'redirect_uri': redirect_uri,
                'scope': validated_scope,
                'state': state,
                'resource': resource,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
            })

            _logger.info("OAuth: Authorization code created for user %s, client %s",
                        request.env.user.login, client.client_name)

            # Redirect with code
            redirect_url = f"{redirect_uri}?code={auth_code.code}"
            if state:
                redirect_url += f"&state={state}"

            # Only redirect_uri is logged: redirect_url carries the authorization code, a
            # credential that must not reach the log.
            _logger.info("OAuth authorize: Redirecting to '%s'", redirect_uri)

            # Show success page with delayed redirect via JavaScript.
            # This provides better UX than a direct 302 redirect which leaves
            # the consent page spinning while the browser follows the redirect.
            # NOTE: The redirect_url may be external (e.g., claude.ai callback or
            # localhost for Claude Desktop) - the JS redirect handles this properly.
            return request.render('inouk_api_auth.oauth_consent_success', {
                'client_name': client.client_name,
                'redirect_url': redirect_url,
            })

        # ═══════════════════════════════════════════════════════════════════════
        # DISPLAY CONSENT SCREEN
        # ═══════════════════════════════════════════════════════════════════════

        # Parse scopes for display. Hardcoded fallback labels — used only by
        # the global /oauth/authorize controller for non-MCP clients. The MCP
        # per-instance controller (inouk_mcp.mcp_oauth) reads labels from the
        # provider's scopes_yaml as the single source of truth.
        scope_list = validated_scope.split() if validated_scope else []
        scope_descriptions = {
            'mcp:discovery': ('Discovery', 'List available domains and models'),
            'mcp:source': ('Source Code', 'Read Python method source code'),
            'mcp:read': ('Read Data', 'Search and read records from the database'),
            'mcp:write': ('Write Data', 'Create, modify, and delete records'),
            'mcp:execute': ('Execute Methods', 'Call whitelisted methods on records'),
        }

        scopes_display = []
        for s in scope_list:
            if s in scope_descriptions:
                name, desc = scope_descriptions[s]
                scopes_display.append({'name': name, 'description': desc, 'scope': s})
            else:
                scopes_display.append({'name': s, 'description': '', 'scope': s})

        return request.render('inouk_api_auth.oauth_consent', {
            'client': client,
            'scopes': scopes_display,
            'redirect_uri': redirect_uri,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'resource': resource,
            'scope': validated_scope,
            'user': request.env.user,
        })

    # ═══════════════════════════════════════════════════════════════════════════
    # TOKEN ENDPOINT
    # ═══════════════════════════════════════════════════════════════════════════

    @http.route('/oauth/token', type='http', auth='none', methods=['POST'],
                csrf=False, save_session=False)
    def oauth_token(self, **kwargs):
        """OAuth 2.0/2.1 Token Endpoint.

        Supports:
        - grant_type=client_credentials (M2M, backward compatible)
        - grant_type=authorization_code (OAuth 2.1 with PKCE)
        - grant_type=refresh_token
        - grant_type=urn:ietf:params:oauth:grant-type:device_code (RFC 8628)
        """
        # Parse request (support both form-urlencoded and JSON)
        content_type = request.httprequest.content_type or ''
        if 'application/json' in content_type:
            try:
                data = json.loads(request.httprequest.get_data(as_text=True))
            except json.JSONDecodeError:
                return self._oauth_error('invalid_request', 'Invalid JSON', 400)
        else:
            data = dict(kwargs)

        grant_type = data.get('grant_type')

        _logger.debug("OAuth token request: grant_type=%s from %s",
                     grant_type, request.httprequest.remote_addr)

        if grant_type == 'authorization_code':
            return self._token_authorization_code(data)
        elif grant_type == 'refresh_token':
            return self._token_refresh(data)
        elif grant_type == 'client_credentials':
            return self._token_client_credentials(data)
        elif grant_type == 'urn:ietf:params:oauth:grant-type:device_code':
            return self._token_device_code(data)
        else:
            return self._oauth_error('unsupported_grant_type',
                                     f"Grant type '{grant_type}' not supported", 400)

    def _token_authorization_code(self, data):
        """Handle authorization_code grant type."""
        code = data.get('code')
        redirect_uri = data.get('redirect_uri')
        client_id = data.get('client_id')
        code_verifier = data.get('code_verifier')
        resource = data.get('resource')

        # Validate required parameters
        if not all([code, redirect_uri, client_id, code_verifier]):
            return self._oauth_error(
                'invalid_request',
                'code, redirect_uri, client_id, and code_verifier are required',
                400
            )

        # Lookup authorization code
        AuthCode = request.env['ik.oauth_authorization_code'].sudo()
        auth_code = AuthCode.search([
            ('code', '=', code),
            ('client_id', '=', client_id),
        ], limit=1)

        if not auth_code:
            return self._oauth_error('invalid_grant', 'Authorization code not found', 400)

        # Validate PKCE
        try:
            auth_code.validate_pkce(code_verifier)
        except ValidationError as e:
            return self._oauth_error('invalid_grant', str(e), 400)

        # Validate redirect_uri matches
        if auth_code.redirect_uri != redirect_uri:
            return self._oauth_error('invalid_grant', 'redirect_uri mismatch', 400)

        # Consume the code (marks as used, checks expiration)
        try:
            auth_code.consume()
        except ValidationError as e:
            return self._oauth_error('invalid_grant', str(e), 400)

        # Generate access token
        return self._issue_tokens(
            auth_code.client_registration_id,
            auth_code.user_id,
            auth_code.scope,
            resource or auth_code.resource
        )

    def _token_refresh(self, data):
        """Handle refresh_token grant type."""
        refresh_token_value = data.get('refresh_token')
        client_id = data.get('client_id')
        scope = data.get('scope')  # Optional: request subset of original scopes

        if not refresh_token_value:
            return self._oauth_error('invalid_request', 'refresh_token is required', 400)

        # Lookup refresh token
        RefreshToken = request.env['ik.oauth_refresh_token'].sudo()
        refresh_token = RefreshToken.search([
            ('token', '=', refresh_token_value),
        ], limit=1)

        if not refresh_token:
            return self._oauth_error('invalid_grant', 'Refresh token not found', 400)

        # Validate client_id if provided
        if client_id and refresh_token.client_id != client_id:
            return self._oauth_error('invalid_grant', 'client_id mismatch', 400)

        # Validate refresh token
        try:
            refresh_token.validate()
        except ValidationError as e:
            return self._oauth_error('invalid_grant', str(e), 400)

        # Validate scope (can only be equal or subset of original)
        if scope:
            requested = set(scope.split())
            original = set((refresh_token.scope or '').split())
            if not requested.issubset(original):
                return self._oauth_error('invalid_scope', 'Requested scope exceeds original grant', 400)
            final_scope = scope
        else:
            final_scope = refresh_token.scope

        # Revoke old access token
        if refresh_token.access_token_id:
            refresh_token.access_token_id.write({'is_compromised': True})

        # Issue new tokens
        return self._issue_tokens(
            refresh_token.client_registration_id,
            refresh_token.user_id,
            final_scope,
            refresh_token.resource,
            old_refresh_token=refresh_token
        )

    def _token_client_credentials(self, data):
        """Handle client_credentials grant type (backward compatible)."""
        client_id = data.get('client_id')
        client_secret = data.get('client_secret')

        if not client_id or not client_secret:
            return self._oauth_error('invalid_request',
                                     'client_id and client_secret are required', 400)

        # Lookup OAuth client (old model)
        client = request.env['ik.api_auth_token'].sudo().search([
            ('oauth_client_id', '=', client_id),
            ('token_type', '=', 'oauth_client'),
        ], limit=1)

        if not client:
            _logger.warning("OAuth: Unknown client_id: %s", client_id)
            return self._oauth_error('invalid_client', 'Unknown client_id', 401)

        # Validate client_secret (constant-time comparison)
        if not secrets.compare_digest(client.oauth_client_secret or '', client_secret or ''):
            _logger.warning("OAuth: Invalid credentials for client_id: %s", client_id)
            return self._oauth_error('invalid_client', 'Invalid credentials', 401)

        # Check client status
        if client.is_compromised:
            _logger.warning("OAuth: Compromised client attempted access: %s", client_id)
            return self._oauth_error('invalid_client', 'Client is disabled', 401)

        if client.expiration_ts and client.expiration_ts <= fields.Datetime.now():
            return self._oauth_error('invalid_client', 'Client credentials expired', 401)

        # Generate new Bearer token
        bearer_token = client.generate_access_token()
        expires_in = client.oauth_token_lifetime or 3600

        _logger.info("OAuth: Issued client_credentials token for %s", client.name)

        return self._token_response(
            access_token=bearer_token.static_token,
            token_type='Bearer',
            expires_in=expires_in,
        )

    def _token_device_code(self, data):
        """Handle device_code grant type (RFC 8628)."""
        device_code = data.get('device_code')
        client_id = data.get('client_id')

        if not device_code:
            return self._oauth_error('invalid_request', 'device_code is required', 400)
        if not client_id:
            return self._oauth_error('invalid_request', 'client_id is required', 400)

        # Lookup device authorization
        DeviceCode = request.env['ik.oauth_device_code'].sudo()
        device_auth = DeviceCode.search([
            ('device_code', '=', device_code),
        ], limit=1)

        if not device_auth:
            return self._oauth_error('invalid_grant', 'Device code not found', 400)

        # Validate client
        if device_auth.client_registration_id.client_id != client_id:
            return self._oauth_error('invalid_grant', 'client_id mismatch', 400)

        # Check authorization status
        status = device_auth.check_authorization_status()

        if 'error' in status:
            return self._oauth_error(status['error'], status.get('error_description', ''), 400)

        if status.get('status') == 'authorized':
            # Issue tokens
            result = self._issue_tokens(
                device_auth.client_registration_id,
                status['user_id'],
                status['scope'],
                device_auth.resource
            )

            # Clean up device code
            device_auth.unlink()

            return result

        return self._oauth_error('server_error', 'Unexpected state', 500)

    def _issue_tokens(self, client_registration, user, scope, resource, old_refresh_token=None):
        """Issue access and refresh tokens.

        Thin wrapper over ``ik.oauth_refresh_token.issue_token_pair()``. Wraps
        the dict returned by the classmethod in an HTTP Response. The classmethod
        is the canonical implementation — addons that need to inject extra fields
        (e.g. inouk_mcp adding ``mcp_instance_id``) call it directly with
        ``extra_access_vals`` / ``extra_refresh_vals``.

        Returns:
            Response: RFC 6749 token response.
        """
        token_payload = request.env['ik.oauth_refresh_token'].issue_token_pair(
            client_registration, user, scope, resource,
            old_refresh_token=old_refresh_token,
        )
        _logger.info("OAuth: Issued OAuth 2.1 token for user %s, client %s",
                    user.login, client_registration.client_name)
        return self._token_response(**token_payload)

    def _token_response(self, access_token, token_type, expires_in,
                        refresh_token=None, scope=None):
        """Build standard token response."""
        response = {
            'access_token': access_token,
            'token_type': token_type,
            'expires_in': expires_in,
        }

        if refresh_token:
            response['refresh_token'] = refresh_token

        if scope:
            response['scope'] = scope

        return Response(
            json.dumps(response),
            content_type='application/json',
            headers={
                'Cache-Control': 'no-store',
                'Pragma': 'no-cache',
            }
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # DEVICE AUTHORIZATION ENDPOINTS (RFC 8628)
    # ═══════════════════════════════════════════════════════════════════════════

    @http.route('/oauth/device/code', type='http', auth='none', methods=['POST'],
                csrf=False, save_session=False)
    def oauth_device_code(self, **kwargs):
        """RFC 8628 Device Authorization Request.

        Called by CLI to initiate device flow.
        """
        client_id = kwargs.get('client_id')
        scope = kwargs.get('scope', '')
        resource = kwargs.get('resource')

        if not client_id:
            return self._oauth_error('invalid_request', 'client_id is required', 400)

        # Lookup client registration
        ClientReg = request.env['ik.oauth_client_registration'].sudo()
        client = ClientReg.search([
            ('client_id', '=', client_id),
            ('active', '=', True),
        ], limit=1)

        if not client:
            return self._oauth_error('invalid_client', 'Client not found or inactive', 401)

        # Validate device flow is allowed for this client
        if not client.has_grant_type('urn:ietf:params:oauth:grant-type:device_code'):
            return self._oauth_error('unauthorized_client',
                                     'Client not authorized for device code flow', 400)

        # Create device authorization
        DeviceCode = request.env['ik.oauth_device_code'].sudo()
        response = DeviceCode.create_device_authorization(client, scope=scope, resource=resource)

        _logger.info("OAuth: Device code created for client %s", client.client_name)

        return Response(
            json.dumps(response),
            content_type='application/json',
            headers={
                'Cache-Control': 'no-store',
                'Pragma': 'no-cache',
            }
        )

    @http.route('/oauth/device', type='http', auth='public', methods=['GET'], csrf=False)
    def oauth_device_verify(self, **kwargs):
        """RFC 8628 Device Verification Endpoint.

        User visits this URL to authorize the CLI.
        """
        device_code = kwargs.get('code')
        user_code = kwargs.get('user_code')

        # Require authentication
        if not request.session.uid:
            # Redirect to login, preserving the return URL
            return request.redirect(f'/web/login?redirect={request.httprequest.url}')

        user = request.env['res.users'].sudo().browse(request.session.uid)

        DeviceCode = request.env['ik.oauth_device_code'].sudo()

        # Find the device authorization
        if device_code:
            device_auth = DeviceCode.search([
                ('device_code', '=', device_code),
                ('state', '=', 'pending'),
            ], limit=1)
        elif user_code:
            # Normalize user code (remove dashes, uppercase)
            normalized_code = user_code.upper().replace(' ', '').replace('-', '')
            # Search with dash format
            device_auth = DeviceCode.search([
                ('user_code', 'ilike', f'%{normalized_code[:4]}%{normalized_code[4:]}%'),
                ('state', '=', 'pending'),
            ], limit=1)
        else:
            # Show form to enter user_code manually
            return request.render('inouk_api_auth.oauth_device_enter_code', {})

        if not device_auth:
            return request.render('inouk_api_auth.oauth_device_error', {
                'error': 'Device authorization not found or already processed.',
            })

        if device_auth.expires_at < fields.Datetime.now():
            device_auth.write({'state': 'expired'})
            return request.render('inouk_api_auth.oauth_device_error', {
                'error': 'Device authorization has expired. Please try again from the CLI.',
            })

        # Parse scopes for display. Hardcoded fallback labels — used by the
        # global /oauth/device controller for non-MCP clients. MCP CLI clients
        # (mgx, mpy) hit this same template after device init, but their scope
        # vocabulary is constrained by the provider's scopes_yaml at issuance
        # time, so this dict only labels what the user already consented to
        # via the MCP-aware code path.
        scopes = []
        if device_auth.scope:
            scope_descriptions = {
                'mcp:discovery': ('Discovery', 'List domains and models'),
                'mcp:source': ('Source Code', 'Read method source code'),
                'mcp:read': ('Read Data', 'Search and read records'),
                'mcp:write': ('Write Data', 'Create, modify, delete records'),
                'mcp:execute': ('Execute', 'Call whitelisted methods'),
            }
            for s in device_auth.scope.split():
                if s in scope_descriptions:
                    name, desc = scope_descriptions[s]
                    scopes.append({'scope': s, 'name': name, 'description': desc})
                else:
                    scopes.append({'scope': s, 'name': s, 'description': ''})

        return request.render('inouk_api_auth.oauth_device_consent', {
            'device_auth': device_auth,
            'client': device_auth.client_registration_id,
            'user': user,
            'scopes': scopes,
        })

    @http.route('/oauth/device/authorize', type='http', auth='user', methods=['POST'], csrf=True)
    def oauth_device_authorize(self, **kwargs):
        """Handle device authorization consent."""
        device_code = kwargs.get('device_code')
        action = kwargs.get('action')

        if not device_code or action not in ('authorize', 'deny'):
            return request.render('inouk_api_auth.oauth_device_error', {
                'error': 'Invalid request.',
            })

        DeviceCode = request.env['ik.oauth_device_code'].sudo()
        device_auth = DeviceCode.search([
            ('device_code', '=', device_code),
            ('state', '=', 'pending'),
        ], limit=1)

        if not device_auth:
            return request.render('inouk_api_auth.oauth_device_error', {
                'error': 'Device authorization not found or already processed.',
            })

        user = request.env.user

        if action == 'authorize':
            try:
                device_auth.authorize(user)
                _logger.info("OAuth: Device code authorized for user %s, client %s",
                            user.login, device_auth.client_registration_id.client_name)
                return request.render('inouk_api_auth.oauth_device_success', {
                    'client': device_auth.client_registration_id,
                })
            except ValidationError as e:
                return request.render('inouk_api_auth.oauth_device_error', {
                    'error': str(e),
                })
        else:
            device_auth.deny()
            _logger.info("OAuth: Device code denied for client %s",
                        device_auth.client_registration_id.client_name)
            return request.render('inouk_api_auth.oauth_device_denied', {
                'client': device_auth.client_registration_id,
            })

    # ═══════════════════════════════════════════════════════════════════════════
    # ERROR HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _oauth_error(self, error, description=None, status=400):
        """Return OAuth error response."""
        body = {'error': error}
        if description:
            body['error_description'] = description

        # Status codes per RFC 6749
        if error == 'invalid_client':
            status = 401

        return Response(
            json.dumps(body),
            status=status,
            content_type='application/json'
        )

    def _oauth_error_redirect(self, redirect_uri, state, error, description):
        """Redirect with OAuth error parameters."""
        if not redirect_uri:
            return self._oauth_error(error, description, 400)

        params = {'error': error, 'error_description': description}
        if state:
            params['state'] = state

        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        # local=False: Allow redirect to external domains (OAuth clients like claude.ai)
        return request.redirect(redirect_url, local=False)
