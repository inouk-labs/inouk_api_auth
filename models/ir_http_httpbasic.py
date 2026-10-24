# -*- coding: utf-8 -*-
import base64
import logging

from odoo import models, fields
from odoo.http import request
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class IrHttpBasic(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_ik_httpbasicauth(cls):
        """Authentication method for HTTP Basic Authentication

        This method implements HTTP Basic Authentication as defined in RFC 7617
        https://tools.ietf.org/html/rfc7617

        The credentials must be provided in the Authorization header:
        Authorization: Basic <base64-encoded-username:password>
        """
        # Get request information for security checks
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')

        # Extract Authorization header
        auth_header = request.httprequest.headers.get('Authorization', '')
        if not auth_header.lower().startswith('basic '):
            raise AccessDenied("Missing or invalid Basic Authorization header.")

        # Decode the base64 credentials
        try:
            encoded_credentials = auth_header.split(' ', 1)[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(':', 1)
            # Nothing derived from the decoded user name is written: a client that swaps user and
            # password would log the password.
            _logger.info("HTTP Basic auth - credential received")
        except (IndexError, ValueError, UnicodeDecodeError) as e:
            _logger.warning("HTTP Basic auth - Failed to decode credentials (%s)", type(e).__name__)
            raise AccessDenied("Invalid Basic Authorization format.")

        # Search for token in database by username
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('httpbasicauth_username', '=', username),
            ('token_type', '=', 'httpbasicauth'),
        ], order='id DESC', limit=1)

        # Decision tree based on token status
        if not token_obj:
            _logger.warning("HTTP Basic authentication failed - no token found for the user name received")
            raise AccessDenied("Invalid credentials.")
        elif token_obj.is_compromised:
            _logger.warning("HTTP Basic authentication failed - token %s (ID: %s) is compromised",
                          token_obj.name, token_obj.id)
            raise AccessDenied("Invalid credentials.")
        elif token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("HTTP Basic authentication failed - token %s (ID: %s) expired at %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts)
            raise AccessDenied("Invalid credentials.")

        # Validate password against stored password
        if not token_obj.httpbasicauth_password:
            _logger.warning("HTTP Basic authentication failed - no password for token %s", token_obj.name)
            raise AccessDenied("Invalid credentials.")

        if token_obj.httpbasicauth_password != password:
            _logger.warning("HTTP Basic authentication failed - invalid password for token %s (ID: %s)", token_obj.name, token_obj.id)
            raise AccessDenied("Invalid credentials.")

        # Check if token was sent over HTTPS
        is_compromised = cls._check_token_compromised(request, http_referer)

        if is_compromised:
            if token_obj.enforce_integrity:
                # Mark token as compromised and expire it
                cls._compromise_token(token_obj, sender_ip)
                raise AccessDenied("Invalid credentials.")
            else:
                _logger.warning("HTTP Basic token %s received over unsecure 'http' from %s.", token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.update_env(user=user_obj.id)

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Build auth details specific to HTTP Basic
        auth_details = {
            'username': username,
            'encoding': 'base64',  # HTTP Basic always uses base64 encoding
        }

        # Build and store complete auth context
        request.inouk_api_auth = cls._build_auth_context(
            token_obj=token_obj,
            auth_type='httpbasicauth',
            auth_details=auth_details
        )

        # Keep legacy attribute for backward compatibility
        request.inouk_token_obj = token_obj

        _logger.debug("User %s authenticated via HTTP Basic token %s", user_obj.name, token_obj.name)