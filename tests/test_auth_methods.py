# -*- coding: utf-8 -*-
import secrets
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from odoo import fields
from odoo.tests.common import TransactionCase, tagged
from odoo.exceptions import AccessDenied

from .common import patched_request


@tagged('post_install', '-at_install')
class TestAuthMethods(TransactionCase):
    """Test authentication methods"""

    def setUp(self):
        super().setUp()
        self.api_user = self.env['res.users'].create({
            'name': 'API Auth Test User',
            'login': 'api_auth_test_user',
            'email': 'api_auth_test_user@example.com',
        })
        self.token_value = secrets.token_hex(30)
        self.test_token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.api_user.id,
            'static_token': self.token_value,
            'token_type': 'bearer',
            'enforce_integrity': True,
        })

    def _create_mock_request(self, headers=None, url='https://test.example.com/api', params=None, args=None):
        """Create a mock request object"""
        mock_request = MagicMock()
        mock_request.env = self.env
        mock_request.session = MagicMock(sid='test-session-sid')
        mock_request.httprequest.headers = dict(headers or {})
        mock_request.httprequest.url = url
        mock_request.httprequest.environ = {
            'REMOTE_ADDR': '192.168.1.100',
            'HTTP_REFERER': 'https://test.example.com',
        }
        mock_request.params = params or {}
        mock_request.httprequest.args = dict(args or {})
        return mock_request

    def test_auth_method_ik_bearer_with_authorization_header(self):
        """Test authentication with Authorization header"""
        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {self.token_value}'
        })

        with patched_request(mock_request):
            # Call the authentication method
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            # Verify authentication
            mock_request.update_env.assert_called_with(user=self.api_user.id)
            self.assertEqual(mock_request.inouk_token_obj, self.test_token)

    def test_auth_method_ik_bearer_with_gitlab_header(self):
        """Test authentication with X-Gitlab-Token header"""
        gitlab_token = self.env['ik.api_auth_token'].create({
            'name': 'GitLab Token',
            'user_id': self.api_user.id,
            'static_token': self.token_value + 'gitlab',
            'token_type': 'xgitlabtoken',
        })

        mock_request = self._create_mock_request(headers={
            'X-Gitlab-Token': gitlab_token.static_token
        })

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            mock_request.update_env.assert_called_with(user=self.api_user.id)
            self.assertEqual(mock_request.inouk_token_obj, gitlab_token)

    def test_auth_method_ik_bearer_with_url_param(self):
        """Test authentication with URL parameter"""
        mock_request = self._create_mock_request(args={
            'access_token': self.token_value
        })

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            mock_request.update_env.assert_called_with(user=self.api_user.id)

    def test_auth_method_ik_bearer_missing_token(self):
        """Test authentication failure when no token provided"""
        mock_request = self._create_mock_request()

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AccessDenied) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Missing required Authorization", str(cm.exception))

    def test_auth_method_ik_bearer_invalid_token(self):
        """Test authentication failure with invalid token"""
        mock_request = self._create_mock_request(headers={
            'Authorization': 'Bearer invalid_token_value'
        })

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AccessDenied) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    def test_auth_method_ik_bearer_expired_token(self):
        """Test authentication failure with expired token"""
        expired_token = self.env['ik.api_auth_token'].create({
            'name': 'Expired Token',
            'user_id': self.api_user.id,
            'static_token': 'expired_token_value',
            'token_type': 'bearer',
            'expiration_ts': fields.Datetime.now() - timedelta(days=1),
        })

        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {expired_token.static_token}'
        })

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AccessDenied) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    def test_auth_method_ik_bearer_compromised_token(self):
        """Test authentication failure with compromised token"""
        self.test_token.write({'is_compromised': True})

        mock_request = self._create_mock_request(headers={
            'Authorization': f'Bearer {self.token_value}'
        })

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AccessDenied) as cm:
                ir_http._auth_method_ik_bearer()
            self.assertIn("Invalid Access Token", str(cm.exception))

    def test_check_token_compromised_https_ok(self):
        """Test compromission check passes for HTTPS (not compromised)"""
        mock_request = self._create_mock_request(
            url='https://test.example.com/api'
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'https://test.example.com')
            self.assertFalse(is_compromised)

    def test_check_token_compromised_http_fail(self):
        """Test compromission check fails for HTTP (compromised)"""
        mock_request = self._create_mock_request(
            url='http://test.example.com/api'
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'https://test.example.com')
            self.assertTrue(is_compromised)

    def test_check_token_compromised_http_referer_fail(self):
        """Test compromission check fails for HTTP referer (compromised)"""
        mock_request = self._create_mock_request(
            url='https://test.example.com/api'
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            is_compromised = ir_http._check_token_compromised(mock_request, 'http://test.example.com')
            self.assertTrue(is_compromised)

    def test_compromise_token_http_with_integrity(self):
        """Test token gets compromised when received over HTTP with enforce_integrity=True"""
        mock_request = self._create_mock_request(
            url='http://test.example.com/api',
            headers={'Authorization': f'Bearer {self.token_value}'}
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            # _compromise_token commits so that the mark survives the request's rollback;
            # a test cursor refuses a commit. The refusal is caught by hand: Odoo's
            # assertRaises rolls back to a savepoint, which would undo the very write checked below.
            with patch.object(self.env.cr, 'commit'):
                try:
                    ir_http._auth_method_ik_bearer()
                except AccessDenied:
                    pass
                else:
                    self.fail("AccessDenied expected")

            # Check token was compromised
            self.test_token.invalidate_recordset()
            self.assertTrue(self.test_token.is_compromised)
            self.assertIn('Token expired by Muppy', self.test_token.security_log)

    def test_auth_method_ik_bearer_http_without_integrity(self):
        """Test authentication works over HTTP when enforce_integrity=False"""
        self.test_token.write({'enforce_integrity': False})

        mock_request = self._create_mock_request(
            url='http://test.example.com/api',
            headers={'Authorization': f'Bearer {self.token_value}'}
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            ir_http._auth_method_ik_bearer()

            # Should work but generate warning
            mock_request.update_env.assert_called_with(user=self.api_user.id)
            self.assertFalse(self.test_token.is_compromised)

    def test_auth_method_ik_awssigv4_success(self):
        """Test successful AWS SigV4 authentication"""
        from unittest.mock import MagicMock

        # Create AWS SigV4 token
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        mock_request = self._create_mock_request(
            url='https://test.example.com/api',
            headers={
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=example'
            }
        )
        mock_request.httprequest.method = 'GET'
        mock_request.httprequest.get_data.return_value = b''

        with patched_request(mock_request):
            with patch.object(self.env.registry['ir.http'], '_validate_awssigv4_signature', return_value=True):
                ir_http = self.env['ir.http']
                ir_http._auth_method_ik_awssigv4()

                mock_request.update_env.assert_called_with(user=self.api_user.id)
                self.assertEqual(mock_request.inouk_token_obj, aws_token)

    def test_auth_method_ik_awssigv4_invalid_header(self):
        """Test AWS SigV4 authentication with invalid header"""
        mock_request = self._create_mock_request(
            headers={'Authorization': 'Bearer invalid'}
        )

        with patched_request(mock_request):
            ir_http = self.env['ir.http']
            with self.assertRaises(AccessDenied) as cm:
                ir_http._auth_method_ik_awssigv4()
            self.assertIn("Missing or invalid AWS4-HMAC-SHA256", str(cm.exception))

    def test_auth_method_ik_awssigv4_invalid_signature(self):
        """Test AWS SigV4 authentication with invalid signature"""
        # Create AWS SigV4 token
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        mock_request = self._create_mock_request(
            headers={
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20230101/us-east-1/execute-api/aws4_request, SignedHeaders=host;x-amz-date, Signature=invalid'
            }
        )
        mock_request.httprequest.method = 'GET'
        mock_request.httprequest.get_data.return_value = b''

        with patched_request(mock_request):
            with patch.object(self.env.registry['ir.http'], '_validate_awssigv4_signature', return_value=False):
                ir_http = self.env['ir.http']
                with self.assertRaises(AccessDenied) as cm:
                    ir_http._auth_method_ik_awssigv4()
                self.assertIn("Invalid AWS Signature", str(cm.exception))