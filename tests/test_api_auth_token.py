# -*- coding: utf-8 -*-
import secrets
from datetime import datetime, timedelta

from odoo import fields
from odoo.tests.common import TransactionCase, tagged
from odoo.exceptions import UserError
from odoo.addons.inouk_api_auth.controllers.auth import TOKEN_STATUS_CONTROLLER_URL


@tagged('post_install', '-at_install')
class TestAPIAuthToken(TransactionCase):
    """Test API Auth Token model functionality"""

    def setUp(self):
        super().setUp()
        self.api_user = self.env['res.users'].create({
            'name': 'API Auth Test User',
            'login': 'api_auth_test_user',
            'email': 'api_auth_test_user@example.com',
        })

    def test_token_creation_with_default(self):
        """Test that creating a token generates a default static_token"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.api_user.id,
        })

        # Check that static_token was generated
        self.assertTrue(token.static_token)
        # 'ikaa_' + secrets.token_urlsafe(32) = 5 + 43 chars
        self.assertTrue(token.static_token.startswith('ikaa_'))
        self.assertEqual(len(token.static_token), 48)
        self.assertEqual(token.token_type, 'header')
        self.assertFalse(token.is_compromised)
        self.assertTrue(token.enforce_integrity)

    def test_token_uniqueness_constraint(self):
        """Test that the token uniqueness constraint works"""
        token_value = secrets.token_hex(30)

        # Create first token
        self.env['ik.api_auth_token'].create({
            'name': 'Test Token 1',
            'user_id': self.api_user.id,
            'static_token': token_value,
            'token_type': 'bearer',
        })

        # Try to create second token with same token/type - should fail
        with self.assertRaises(Exception):  # Unique constraint violation
            self.env['ik.api_auth_token'].create({
                'name': 'Test Token 2',
                'user_id': self.api_user.id,
                'static_token': token_value,
                'token_type': 'bearer',
            })

    def test_token_uniqueness_different_types(self):
        """Test that same token can exist with different types"""
        token_value = secrets.token_hex(30)

        # Create bearer token
        token1 = self.env['ik.api_auth_token'].create({
            'name': 'Test Bearer Token',
            'user_id': self.api_user.id,
            'static_token': token_value,
            'token_type': 'bearer',
        })

        # Create xgitlabtoken with same value - should work
        token2 = self.env['ik.api_auth_token'].create({
            'name': 'Test GitLab Token',
            'user_id': self.api_user.id,
            'static_token': token_value,
            'token_type': 'xgitlabtoken',
        })

        self.assertEqual(token1.static_token, token2.static_token)
        self.assertNotEqual(token1.token_type, token2.token_type)

    def test_token_expiration(self):
        """Test token expiration functionality"""
        # Create token with future expiration
        future_date = fields.Datetime.now() + timedelta(days=1)
        token = self.env['ik.api_auth_token'].create({
            'name': 'Future Token',
            'user_id': self.api_user.id,
            'expiration_ts': future_date,
        })

        # Token should be found (not expired)
        found_token = self.env['ik.api_auth_token'].search([
            ('static_token', '=', token.static_token),
            ('is_compromised', '=', False),
            '|',
                ('expiration_ts', '=', False),
                ('expiration_ts', '>', fields.Datetime.now()),
        ])
        self.assertEqual(found_token, token)

        # Create token with past expiration
        past_date = fields.Datetime.now() - timedelta(days=1)
        expired_token = self.env['ik.api_auth_token'].create({
            'name': 'Expired Token',
            'user_id': self.api_user.id,
            'expiration_ts': past_date,
        })

        # Token should not be found (expired)
        found_expired = self.env['ik.api_auth_token'].search([
            ('static_token', '=', expired_token.static_token),
            ('is_compromised', '=', False),
            '|',
                ('expiration_ts', '=', False),
                ('expiration_ts', '>', fields.Datetime.now()),
        ])
        self.assertEqual(len(found_expired), 0)

    def test_token_regeneration(self):
        """Test token regeneration functionality"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.api_user.id,
        })
        original_token = token.static_token

        token.btn_regenerate_credentials()

        self.assertTrue(token.static_token.startswith('ikaa_'))
        self.assertNotEqual(token.static_token, original_token)

    def test_token_restore(self):
        """Test token restoration functionality"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.api_user.id,
            'is_compromised': True,
            'expiration_ts': fields.Datetime.now(),
            'security_log': 'Original log',
        })

        token.btn_restore_token()

        self.assertFalse(token.is_compromised)
        self.assertFalse(token.expiration_ts)
        self.assertIn('Token re-enabled by', token.security_log)
        self.assertIn('Original log', token.security_log)

    def test_compute_test_curl_bearer(self):
        """Test curl command generation for bearer tokens"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://test.example.com')

        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Bearer Token',
            'user_id': self.api_user.id,
            'static_token': secrets.token_hex(30),
            'token_type': 'bearer',
            'test_use_header': True,
        })

        # The helper names an environment variable, it never embeds the token.
        self.assertIn('curl --header "Authorization: Bearer $BEARER_TOKEN"', token.test_curl_helper)
        self.assertIn('https://test.example.com' + TOKEN_STATUS_CONTROLLER_URL + '/bearer',
                      token.test_curl_helper)
        self.assertNotIn(token.static_token, token.test_curl_helper)

    def test_compute_test_curl_bearer_url_param(self):
        """Test curl command generation for bearer tokens with URL parameter"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://test.example.com')

        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Bearer Token',
            'user_id': self.api_user.id,
            'static_token': secrets.token_hex(30),
            'token_type': 'bearer',
            'test_use_header': False,
        })

        self.assertIn('?access_token=$BEARER_TOKEN', token.test_curl_helper)
        self.assertNotIn('Authorization: Bearer', token.test_curl_helper)

    def test_compute_test_curl_gitlab(self):
        """Test curl command generation for GitLab tokens"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://test.example.com')

        token = self.env['ik.api_auth_token'].create({
            'name': 'Test GitLab Token',
            'user_id': self.api_user.id,
            'static_token': secrets.token_hex(30),
            'token_type': 'xgitlabtoken',
            'test_use_header': True,
        })

        self.assertIn('curl --header "X-Gitlab-Token: $GITLAB_TOKEN"', token.test_curl_helper)
        self.assertNotIn('Authorization: Bearer', token.test_curl_helper)
        self.assertNotIn(token.static_token, token.test_curl_helper)

    def test_compute_test_curl_no_base_url(self):
        """Test curl command generation when no base URL is set"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', '')

        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Token',
            'user_id': self.api_user.id,
        })

        self.assertEqual(token.test_curl_helper, "# Configure web.base.url first")

    def test_aws_sigv4_token_creation(self):
        """Test AWS SigV4 token creation and field validation"""
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        self.assertEqual(aws_token.token_type, 'awssigv4')
        self.assertEqual(aws_token.awssigv4_access_key_id, 'AKIAIOSFODNN7EXAMPLE')
        self.assertEqual(aws_token.awssigv4_secret_access_key, 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')

    def test_aws_key_generation(self):
        """Test AWS key generation functionality"""
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
        })

        # Generate AWS keys
        aws_token.btn_regenerate_credentials()

        # Check key format
        self.assertTrue(aws_token.awssigv4_access_key_id.startswith('AKIA'))
        self.assertEqual(len(aws_token.awssigv4_access_key_id), 20)
        self.assertEqual(len(aws_token.awssigv4_secret_access_key), 40)

    def test_aws_curl_generation(self):
        """Test AWS SigV4 curl command generation"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://test.example.com')

        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        # Test curl generation
        # The credentials are masked until the user asks to see them.
        command = aws_token.compute__awssigv4_test_curl()
        self.assertIn('export AWS_ACCESS_KEY_ID="your_access_key_here"', command)
        self.assertNotIn('AKIAIOSFODNN7EXAMPLE', command)

        aws_token.show_password = True
        command = aws_token.compute__awssigv4_test_curl()
        self.assertIn('export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"', command)
        self.assertIn('export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', command)

    def test_aws_curl_without_keys(self):
        """Test AWS SigV4 curl generation without keys"""
        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
        })

        curl_command = aws_token.compute__awssigv4_test_curl()
        self.assertEqual(curl_command, "# Generate AWS keys first")

    def test_aws_curl_no_base_url(self):
        """Test AWS SigV4 curl generation without base URL"""
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', '')

        aws_token = self.env['ik.api_auth_token'].create({
            'name': 'AWS SigV4 Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': 'AKIAIOSFODNN7EXAMPLE',
            'awssigv4_secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        })

        curl_command = aws_token.compute__awssigv4_test_curl()
        self.assertEqual(curl_command, "# Configure web.base.url first")