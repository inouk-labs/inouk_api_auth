# -*- coding: utf-8 -*-
import logging

from odoo import models, fields
from odoo.http import request
from odoo.exceptions import AccessDenied

from .log_safety import register_secret_param, token_fingerprint

_logger = logging.getLogger(__name__)


class IrHttpHeader(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_ik_header(cls):
        """Unified authentication method for header-based tokens

        This method supports flexible header-based authentication including:
        - Authorization: Bearer <token> (standard OAuth2/JWT)
        - X-Gitlab-Token: <token> (GitLab webhooks)
        - X-API-Key: <token> (API keys)
        - Custom headers with configurable prefixes
        - URL parameters (configurable names)

        Supports both new flexible header tokens and legacy bearer/xgitlabtoken types.
        """
        # Get request information for security checks
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')

        # Get all active header-based tokens (including legacy types for compatibility)
        token_search_domain = [
            ('token_type', 'in', ['header', 'bearer', 'xgitlabtoken'])
        ]
        header_tokens = request.env['ik.api_auth_token'].sudo().search(token_search_domain)

        if not header_tokens:
            _logger.debug("No header-based tokens configured")
            raise AccessDenied("No valid authentication method available.")

        # Try to extract token from headers first
        token_obj, token_string, auth_source = cls._extract_token_from_headers(header_tokens)

        # Try URL parameters if no header match found
        if not token_obj:
            token_obj, token_string, auth_source = cls._extract_token_from_url_params(header_tokens)

        # If still no token found, raise authentication error
        if not token_obj:
            _logger.warning("Header authentication failed - no matching token found")
            raise AccessDenied("Invalid or missing authentication token.")

        # Validate token status
        cls._validate_token_status(token_obj)

        # Check if token was sent over HTTPS
        is_compromised = cls._check_token_compromised(request, http_referer)
        if is_compromised and token_obj.enforce_integrity:
            cls._compromise_token(token_obj, sender_ip)
            raise AccessDenied("Invalid Access Token.")
        elif is_compromised:
            _logger.warning("Token %s received over unsecure 'http' from %s.", token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.update_env(user=user_obj.id)

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Build auth context
        auth_details = {
            'header_type': auth_source.get('header_name', 'unknown'),
            'token_source': auth_source.get('source_type', 'unknown'),
            'parameter_name': auth_source.get('param_name') if auth_source.get('source_type') == 'url_param' else None
        }

        request.inouk_api_auth = cls._build_auth_context(
            token_obj=token_obj,
            auth_type=token_obj.token_type,
            auth_details=auth_details
        )

        # Keep legacy attribute for backward compatibility
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via %s token %s", user_obj.name, token_obj.token_type, token_obj.name)

    @classmethod
    def _extract_token_from_headers(cls, header_tokens):
        """Extract token from HTTP headers based on token configurations"""
        headers = request.httprequest.headers

        # Build unique header configurations to check
        headers_to_check = {}

        for token in header_tokens:
            if token.token_type == 'header':
                # Use flexible configuration
                header_name = token.actual_header_name
                prefix = token.actual_header_prefix or ''
            elif token.token_type == 'bearer':
                # Legacy bearer token
                header_name = 'Authorization'
                prefix = 'Bearer '
            elif token.token_type == 'xgitlabtoken':
                # Legacy GitLab token
                header_name = 'X-Gitlab-Token'
                prefix = ''
            else:
                continue

            if header_name:
                headers_to_check[header_name] = prefix

        # Check each header configuration
        for header_name, prefix in headers_to_check.items():
            header_value = headers.get(header_name)
            if not header_value:
                continue

            # Extract token based on prefix
            extracted_token = None
            if prefix and header_value.startswith(prefix):
                extracted_token = header_value[len(prefix):].strip()
            elif not prefix:
                extracted_token = header_value.strip()

            if not extracted_token:
                _logger.info("Received header '%s': it does not carry the expected prefix %r", header_name, prefix)
                continue
            _logger.info("Received header '%s': fingerprint %s", header_name, token_fingerprint(request.env, extracted_token))

            # Find matching token in database
            token_obj = cls._find_matching_token(
                header_tokens, extracted_token, header_name, prefix
            )

            if token_obj:
                auth_source = {
                    'source_type': 'header',
                    'header_name': header_name,
                    'prefix': prefix
                }
                return token_obj, extracted_token, auth_source

        return None, None, None

    @classmethod
    def _extract_token_from_url_params(cls, header_tokens):
        """Extract token from URL parameters based on token configurations"""
        # Build unique parameter names to check from tokens that support URL params
        params_to_check = set()

        for token in header_tokens:
            if not getattr(token, 'support_url_param', True):
                continue

            if token.token_type == 'header':
                param_name = token.actual_url_param_name or 'access_token'
            elif token.token_type in ['bearer', 'xgitlabtoken']:
                param_name = 'access_token'  # Legacy default
            else:
                continue

            params_to_check.add(param_name)
            register_secret_param(param_name)  # its value is masked in the access log

        # Check each parameter (Odoo 18: use httprequest.args instead of request.params)
        for param_name in params_to_check:
            param_value = request.httprequest.args.get(param_name)

            if not param_value:
                continue

            _logger.info("Received URL parameter '%s': fingerprint %s", param_name, token_fingerprint(request.env, param_value))

            # Find matching token that allows this parameter
            token_obj = cls._find_matching_url_param_token(
                header_tokens, param_value, param_name
            )

            if token_obj:
                auth_source = {
                    'source_type': 'url_param',
                    'param_name': param_name
                }
                return token_obj, param_value, auth_source

        return None, None, None

    @classmethod
    def _find_matching_token(cls, header_tokens, extracted_token, header_name, prefix):
        """Find token that matches the extracted token and header configuration"""
        for token in header_tokens:
            if token.static_token != extracted_token:
                continue

            # Check if this token matches the header configuration
            if token.token_type == 'header':
                if (token.actual_header_name == header_name and
                    (token.actual_header_prefix or '') == prefix):
                    return token
            elif token.token_type == 'bearer':
                if header_name == 'Authorization' and prefix == 'Bearer ':
                    return token
            elif token.token_type == 'xgitlabtoken':
                if header_name == 'X-Gitlab-Token' and prefix == '':
                    return token

        return None

    @classmethod
    def _find_matching_url_param_token(cls, header_tokens, param_value, param_name):
        """Find token that matches the URL parameter value and supports this parameter"""
        for token in header_tokens:
            if token.static_token != param_value:
                continue

            # Check if token allows URL params and matches parameter name
            if not getattr(token, 'support_url_param', True):
                continue

            if token.token_type == 'header':
                expected_param = token.actual_url_param_name or 'access_token'
                if expected_param == param_name:
                    return token
            elif token.token_type in ['bearer', 'xgitlabtoken']:
                # Legacy tokens always use access_token
                if param_name == 'access_token':
                    return token

        return None

    @classmethod
    def _validate_token_status(cls, token_obj):
        """Validate that the token is not compromised or expired"""
        if token_obj.is_compromised:
            _logger.warning("Authentication failed - token %s (ID: %s) is compromised",
                          token_obj.name, token_obj.id)
            raise AccessDenied("Invalid Access Token.")

        if token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("Authentication failed - token %s (ID: %s) expired at %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts)
            raise AccessDenied("Invalid Access Token.")

    @classmethod
    def _auth_method_ik_bearer(cls):
        """Legacy Bearer authentication - redirects to unified header auth"""
        return cls._auth_method_ik_header()