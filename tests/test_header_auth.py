import logging
from datetime import timedelta
from unittest.mock import patch, MagicMock
from odoo.tests.common import TransactionCase
from odoo.tests import tagged
from odoo.exceptions import AccessDenied
from odoo import fields

from .common import patched_request

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install')
class TestHeaderAuthentication(TransactionCase):
    """Test the unified header authentication handler"""

    def setUp(self):
        super().setUp()
        self.user = self.env.ref('base.user_admin')
        self.mock_request = MagicMock()
        request_patch = patched_request(self.mock_request)
        request_patch.__enter__()
        self.addCleanup(request_patch.__exit__, None, None, None)

        # Create test tokens
        self.header_token = self.env['ik.api_auth_token'].create({
            'name': 'Header Test Token',
            'token_type': 'header',
            'static_token': 'header_test_123',
            'header_name': 'X-API-Key',
            'header_prefix': '',
            'actual_header_name': 'X-API-Key',
            'actual_header_prefix': '',
            'support_url_param': True,
            'url_param_name': 'api_key',
            'actual_url_param_name': 'api_key',
            'user_id': self.user.id
        })

        self.bearer_token = self.env['ik.api_auth_token'].create({
            'name': 'Bearer Test Token',
            'token_type': 'bearer',
            'static_token': 'bearer_test_456',
            'user_id': self.user.id
        })

        self.gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Test Token',
            'token_type': 'xgitlabtoken',
            'static_token': 'gitlab_test_789',
            'user_id': self.user.id
        })

    def test_header_authentication_success(self):
        """Test successful authentication with custom header"""
        mock_request = self.mock_request
        # Mock request setup
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'header_test_123'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        # Mock the auth context building methods
        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            # Test authentication
            self.env['ir.http']._auth_method_ik_header()

            # Verify user was authenticated
            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_bearer_header_authentication(self):
        """Test authentication with Authorization Bearer header"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'Authorization': 'Bearer bearer_test_456'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            self.env['ir.http']._auth_method_ik_header()
            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_gitlab_token_header_authentication(self):
        """Test authentication with X-Gitlab-Token header"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-Gitlab-Token': 'gitlab_test_789'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            self.env['ir.http']._auth_method_ik_header()
            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_url_parameter_authentication(self):
        """Test authentication with URL parameter"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {}
        mock_request.params = {}
        mock_request.httprequest.args = {'api_key': 'header_test_123'}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            self.env['ir.http']._auth_method_ik_header()

            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_legacy_bearer_url_param(self):
        """Test legacy bearer token with access_token URL parameter"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {}
        mock_request.params = {}
        mock_request.httprequest.args = {'access_token': 'bearer_test_456'}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            self.env['ir.http']._auth_method_ik_header()
            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_invalid_token(self):
        """Test authentication failure with invalid token"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'invalid_token'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.env = self.env

        with self.assertRaises(AccessDenied) as cm:
            self.env['ir.http']._auth_method_ik_header()

        self.assertIn('Invalid or missing authentication token', str(cm.exception))

    def test_no_header_no_param(self):
        """Test authentication failure with no token provided"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.env = self.env

        with self.assertRaises(AccessDenied):
            self.env['ir.http']._auth_method_ik_header()

    def test_compromised_token(self):
        """Test authentication failure with compromised token"""
        mock_request = self.mock_request
        # Mark token as compromised
        self.header_token.is_compromised = True

        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'header_test_123'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.env = self.env

        with self.assertRaises(AccessDenied) as cm:
            self.env['ir.http']._auth_method_ik_header()

        self.assertIn('Invalid Access Token', str(cm.exception))

    def test_expired_token(self):
        """Test authentication failure with expired token"""
        mock_request = self.mock_request
        # Set token as expired
        past_date = fields.Datetime.now() - timedelta(hours=1)
        self.header_token.expiration_ts = past_date

        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'header_test_123'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.env = self.env

        with self.assertRaises(AccessDenied):
            self.env['ir.http']._auth_method_ik_header()

    def test_http_integrity_violation(self):
        """Test token compromised due to HTTP (not HTTPS) usage"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'header_test_123'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = False  # Not HTTPS
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        # Token enforces integrity
        self.header_token.enforce_integrity = True

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=True), \
             patch.object(self.env.registry['ir.http'], '_compromise_token') as mock_compromise:

            with self.assertRaises(AccessDenied):
                self.env['ir.http']._auth_method_ik_header()

            # Verify token was marked as compromised
            mock_compromise.assert_called_once()

    def test_header_priority_over_url_param(self):
        """Test that headers take priority over URL parameters"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'X-API-Key': 'header_test_123'}
        mock_request.params = {}
        mock_request.httprequest.args = {'api_key': 'bearer_test_456'}  # Different token in URL
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}) as mock_build:

            self.env['ir.http']._auth_method_ik_header()

            # Should authenticate with header token, not URL param token
            mock_request.update_env.assert_called_with(user=self.user.id)

            # Verify auth context was built with header token
            mock_build.assert_called_once()
            args, kwargs = mock_build.call_args
            self.assertEqual(kwargs['token_obj'], self.header_token)

    def test_multiple_headers_first_match_wins(self):
        """Test that first matching header is used when multiple headers present"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {
            'Authorization': 'Bearer bearer_test_456',
            'X-API-Key': 'header_test_123'
        }
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            self.env['ir.http']._auth_method_ik_header()
            mock_request.update_env.assert_called_with(user=self.user.id)

    def test_url_param_disabled_token(self):
        """Test URL parameter is ignored when token doesn't support it"""
        mock_request = self.mock_request
        # Disable URL parameter support
        self.header_token.support_url_param = False

        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {}
        mock_request.params = {}
        mock_request.httprequest.args = {'api_key': 'header_test_123'}
        mock_request.env = self.env

        with self.assertRaises(AccessDenied):
            self.env['ir.http']._auth_method_ik_header()

    def test_legacy_bearer_compatibility(self):
        """Test that legacy _auth_method_ik_bearer still works"""
        mock_request = self.mock_request
        mock_request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        mock_request.httprequest.headers = {'Authorization': 'Bearer bearer_test_456'}
        mock_request.params = {}
        mock_request.httprequest.args = {}
        mock_request.httprequest.is_secure = True
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')

        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}):

            # Call legacy method - should redirect to new method
            self.env['ir.http']._auth_method_ik_bearer()
            mock_request.update_env.assert_called_with(user=self.user.id)