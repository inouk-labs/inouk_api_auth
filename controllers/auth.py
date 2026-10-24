"""
Inouk API Auth Controllers
==========================

JSON Handling in Odoo Routes (Odoo 18)
--------------------------------------

This module provides API authentication endpoints. Understanding Odoo's route type
behavior is essential when designing API endpoints.

**Route Types and Content-Type Handling:**

1. ``type='http'`` routes:
   - Form-urlencoded (application/x-www-form-urlencoded):
     - Data automatically parsed into **kwargs
   - JSON (application/json):
     - Raw body available via ``request.httprequest.get_data(as_text=True)``
     - Must manually parse with ``json.loads()``
   - Returns: Response object (raw HTTP response)

2. ``type='json'`` routes (default Odoo behavior):
   - Expects JSON-RPC 2.0 format: ``{"jsonrpc": "2.0", "method": "call", "params": {...}}``
   - REJECTS non-JSON content types with HTTP 400:
     ``"Request inferred type is compatible with ['http'] but 'X' is type='json'"``

3. ``type='json'`` + ``ik_plain_json=True`` routes (inouk_api_auth extension):
   - Accepts plain JSON (no JSON-RPC wrapper needed)
   - Response is plain JSON (no JSON-RPC wrapper)
   - ALSO rejects non-JSON content types (same 400 error)
   - Implemented via monkey-patch in ``json_plain_patch.py``

**Choosing the Right Route Type:**

- Use ``type='http'`` when you need to support BOTH form-urlencoded AND JSON
  (e.g., OAuth /oauth/token endpoint which must support form-urlencoded per RFC 6749)

- Use ``type='json'`` + ``ik_plain_json=True`` for pure JSON REST APIs
  (e.g., internal API calls, external webhooks)

**Dual-Format Handler Pattern (for type='http'):**

.. code-block:: python

    @route('/api/endpoint', type='http', methods=['POST'], auth='public', csrf=False)
    def dual_format_endpoint(self, **kwargs):
        content_type = request.httprequest.content_type or ''

        if 'application/json' in content_type:
            # Parse JSON manually
            data = json.loads(request.httprequest.get_data(as_text=True))
        else:
            # Form-urlencoded - data already in kwargs
            data = kwargs

        # Process data...
        result = {'status': 'success'}
        return Response(json.dumps(result), content_type='application/json')

Tests confirming this behavior: See test script results in git history (2025-12-31).
"""
# ceci est un commentaire
import json
import functools
import timeit
import datetime
import re
import pprint
import logging
import werkzeug.wrappers

from odoo import fields
from odoo.http import Response, request, route, Controller
from odoo.exceptions import AccessDenied
from odoo.tools.safe_eval import safe_eval


_logger = logging.getLogger(__name__)

from ..api import ik_authorize

TEST_CONTROLLER_URL = '/inouk/api_auth/v1/hello'
# Base URL for unified token status endpoints
TOKEN_STATUS_CONTROLLER_URL = '/inouk/api_auth/v2/token/status'

# Important
# All route() must set save_session=False to prevent Odoo from returning a session_id cookie.
#
class InoukAPIAuthControllerV1(Controller):
    """ API to manage inouk_auth_api tokens.
    """
    @ik_authorize
    @route(TEST_CONTROLLER_URL, methods=['GET'], type='http', auth='none', csrf=False, save_session=False)
    def hello(self, *args, **kwargs):
        """ A dump controller to test token using deprecated decorator.
        """
        _logger.info("hello: %d path arguments, %d query parameters", len(args), len([k for k in kwargs if k != 'token_obj']))
        return "Hello ! Call Ok. Received %s\n" % kwargs['token_obj']

    @route(TOKEN_STATUS_CONTROLLER_URL + '/bearer', methods=['GET'], type='http', auth='ik_bearer', csrf=False, save_session=False)
    def token_status_bearer(self, *args, **kwargs):
        """Token status for Bearer/X-Gitlab-Token authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    @route(TOKEN_STATUS_CONTROLLER_URL + '/awssigv4', methods=['GET'], type='http', auth='ik_awssigv4', csrf=False, save_session=False)
    def token_status_awssigv4(self, *args, **kwargs):
        """Token status for AWS SigV4 authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    @route(TOKEN_STATUS_CONTROLLER_URL + '/httpbasic', methods=['GET'], type='http', auth='ik_httpbasicauth', csrf=False, save_session=False)
    def token_status_httpbasic(self, *args, **kwargs):
        """Token status for HTTP Basic authentication"""
        result = self._token_status_unified(*args, **kwargs)
        return Response(json.dumps(result), content_type='application/json')

    def _token_status_unified(self, *args, **kwargs):
        """ Unified token status checker for all authentication methods.

        Returns comprehensive token information in JSON format.
        Supports all authentication methods: Bearer, AWS SigV4, HTTP Basic.
        """
        _logger.info("Token status check - %d path arguments, %d query parameters", len(args), len([k for k in kwargs if k != 'token_obj']))

        # Get auth context created by authentication method
        auth_context = getattr(request, 'inouk_api_auth', None)
        if not auth_context:
            return {
                'error': 'Authentication failed',
                'message': 'No valid authentication context found',
                'status': 'failed'
            }

        try:
            return {
                'status': self._get_token_status_from_context(auth_context),
                'token': self._get_token_info_from_context(auth_context),
                'auth_method': self._get_auth_method_from_context(auth_context),
                'request_info': self._get_request_info_from_context(auth_context)
            }
        except Exception as e:
            _logger.error("Error generating token status: %s", e)
            return {
                'error': 'Internal error',
                'message': 'Failed to generate token status',
                'status': 'error'
            }

    def _get_token_status_from_context(self, auth_context):
        """Get overall token status from auth context"""
        if auth_context.get('is_compromised'):
            return 'compromised'
        elif auth_context.get('is_expired'):
            return 'expired'
        else:
            return 'active'

    def _get_token_info_from_context(self, auth_context):
        """Get safe token information from auth context"""
        token_obj = auth_context.get('token')
        if not token_obj:
            return {}

        token_info = {
            'name': auth_context.get('token_name'),
            'type': auth_context.get('token_type'),
            'user': auth_context.get('user_name'),
            'created': token_obj.create_date.isoformat() if token_obj.create_date else None,
            'is_compromised': auth_context.get('is_compromised'),
            'enforce_https': auth_context.get('enforce_integrity'),
            'description': token_obj.description or None
        }

        # Add expiration info if set
        if token_obj.expiration_ts:
            token_info['expires'] = token_obj.expiration_ts.isoformat()
            now = fields.Datetime.now()
            if token_obj.expiration_ts > now:
                delta = token_obj.expiration_ts - now
                token_info['expires_in_days'] = delta.days
                token_info['expires_in_hours'] = delta.total_seconds() / 3600
            else:
                token_info['expires_in_days'] = 0
                token_info['expires_in_hours'] = 0

        return token_info

    def _get_auth_method_from_context(self, auth_context):
        """Get authentication method specific information from auth context"""
        auth_details = auth_context.get('auth_details', {})
        token_type = auth_context.get('token_type')

        auth_info = {'type': token_type}

        if token_type == 'awssigv4':
            auth_info.update({
                'access_key_id': auth_details.get('access_key_id'),
                'region': auth_details.get('region', 'N/A'),
                'service': auth_details.get('service', 'N/A'),
                'algorithm': auth_details.get('algorithm')
            })
        elif token_type == 'httpbasicauth':
            auth_info.update({
                'username': auth_details.get('username'),
                'encoding': auth_details.get('encoding')
            })
        elif token_type in ['bearer', 'xgitlabtoken']:
            auth_info.update({
                'header_type': auth_details.get('header_type'),
                'token_source': auth_details.get('token_source')
            })

        return auth_info

    def _get_request_info_from_context(self, auth_context):
        """Get safe request information from auth context"""
        request_source = auth_context.get('request_source', {})

        return {
            'authenticated_at': auth_context.get('authenticated_at'),
            'remote_ip': request_source.get('remote_ip', 'unknown'),
            'via': request_source.get('via'),
            'proxy_chain': request_source.get('proxy_chain', []),
            'proxy_type': request_source.get('proxy_type'),
            'using_https': request_source.get('is_https'),
            'user_agent': request_source.get('user_agent', 'unknown'),
            'referer': request_source.get('referer')
        }


# =============================================================================
# Test endpoints for ik_plain_json validation
# =============================================================================
# These endpoints are used to validate that the ik_plain_json monkey-patch
# works correctly in Odoo 18. They test:
# - Plain JSON request/response (no JSON-RPC wrapper)
# - HTTP status codes via werkzeug.exceptions.HTTPException
# - Custom exceptions with status_code attribute
# - Datetime serialization
# - Response object pass-through

from odoo import http
from werkzeug.exceptions import BadRequest, NotFound, Forbidden


class PlainJsonTestError(Exception):
    """Custom exception with status_code attribute for testing"""
    status_code = 422

    def __init__(self, message="Validation error"):
        self.name = message
        super().__init__(message)


class InoukAPIAuthPlainJsonTestController(Controller):
    """Test controller for ik_plain_json validation.

    All endpoints use type='json' with ik_plain_json=True to validate
    the plain JSON (non-JSON-RPC) request/response handling.
    """

    @http.route('/inouk/api_auth/test/plain_json/echo', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_echo(self, **params):
        """Echo back received params as plain JSON.

        Used to test:
        - Plain JSON body is correctly parsed (no JSON-RPC wrapper expected)
        - Response is plain JSON (no JSON-RPC wrapper in response)
        """
        return {'status': 'success', 'echo': params}

    @http.route('/inouk/api_auth/test/plain_json/error_400', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_error_400(self, **params):
        """Raise HTTPException to test 400 status code.

        Used to test that werkzeug.exceptions.BadRequest returns HTTP 400.
        """
        raise BadRequest("Test bad request error")

    @http.route('/inouk/api_auth/test/plain_json/error_404', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_error_404(self, **params):
        """Raise HTTPException to test 404 status code.

        Used to test that werkzeug.exceptions.NotFound returns HTTP 404.
        """
        raise NotFound("Test not found error")

    @http.route('/inouk/api_auth/test/plain_json/error_403', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_error_403(self, **params):
        """Raise HTTPException to test 403 status code.

        Used to test that werkzeug.exceptions.Forbidden returns HTTP 403.
        """
        raise Forbidden("Test forbidden error")

    @http.route('/inouk/api_auth/test/plain_json/error_custom', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_error_custom(self, **params):
        """Raise exception with custom status_code attribute.

        Used to test that exceptions with status_code=422 return HTTP 422.
        """
        raise PlainJsonTestError("Test custom status code error")

    @http.route('/inouk/api_auth/test/plain_json/error_500', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_error_500(self, **params):
        """Raise generic exception to test 500 status code.

        Used to test that unhandled exceptions return HTTP 500.
        """
        raise ValueError("Test internal server error")

    @http.route('/inouk/api_auth/test/plain_json/datetime', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_datetime(self, **params):
        """Test datetime serialization.

        Used to test that datetime objects are correctly serialized via date_utils.json_default.
        """
        return {
            'datetime': datetime.datetime.now(),
            'date': datetime.date.today(),
            'string': 'test',
            'number': 42
        }

    @http.route('/inouk/api_auth/test/plain_json/response_object', type='json', auth='ik_bearer',
                methods=['POST'], csrf=False, save_session=False, ik_plain_json=True)
    def test_plain_json_response_object(self, **params):
        """Test Response object pass-through.

        Used to test that if endpoint returns a Response object, it's returned as-is.
        """
        custom_data = {'custom': 'response', 'with_header': True}
        return Response(
            json.dumps(custom_data),
            status=201,
            headers=[
                ('Content-Type', 'application/json'),
                ('X-Custom-Header', 'test-value')
            ]
        )
