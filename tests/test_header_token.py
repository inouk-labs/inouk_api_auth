import logging
from odoo.tests.common import TransactionCase
from odoo.tests import tagged
from odoo.exceptions import UserError
from odoo.addons.inouk_api_auth.controllers.auth import TOKEN_STATUS_CONTROLLER_URL
from unittest.mock import patch, MagicMock

_logger = logging.getLogger(__name__)


@tagged('post_install', '-at_install')
class TestHeaderToken(TransactionCase):
    """Test the new flexible header-based token system"""

    def setUp(self):
        super().setUp()
        self.user = self.env.ref('base.user_admin')

    def test_service_preset_standard_bearer(self):
        """Test standard Bearer token preset configuration"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Bearer',
            'token_type': 'header',
            'user_id': self.user.id
        })

        # Apply standard bearer preset
        token.service_preset = 'standard_bearer'
        token._onchange_service_preset()

        self.assertEqual(token.header_name, 'Authorization')
        self.assertEqual(token.header_prefix, 'Bearer ')
        self.assertEqual(token.url_param_name, 'access_token')
        self.assertTrue(token.support_url_param)

        # Check computed values
        token._compute_actual_values()
        self.assertEqual(token.actual_header_name, 'Authorization')
        self.assertEqual(token.actual_header_prefix, 'Bearer ')
        self.assertEqual(token.actual_url_param_name, 'access_token')

    def test_service_preset_gitlab_webhook(self):
        """Test GitLab webhook preset configuration"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test GitLab',
            'token_type': 'header',
            'user_id': self.user.id
        })

        token.service_preset = 'gitlab_webhook'
        token._onchange_service_preset()

        self.assertEqual(token.header_name, 'X-Gitlab-Token')
        self.assertFalse(token.header_prefix)  # empty selection value
        self.assertEqual(token.url_param_name, 'access_token')
        self.assertTrue(token.support_url_param)

        token._compute_actual_values()
        self.assertEqual(token.actual_header_name, 'X-Gitlab-Token')
        self.assertEqual(token.actual_header_prefix, '')

    def test_service_preset_api_key(self):
        """Test API key preset configuration"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test API Key',
            'token_type': 'header',
            'user_id': self.user.id
        })

        token.service_preset = 'api_key'
        token._onchange_service_preset()

        self.assertEqual(token.header_name, 'X-API-Key')
        self.assertFalse(token.header_prefix)  # empty selection value
        self.assertEqual(token.url_param_name, 'api_key')
        self.assertTrue(token.support_url_param)

    def test_custom_header_configuration(self):
        """Test custom header configuration"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Custom',
            'token_type': 'header',
            'header_name': 'custom',
            'custom_header_name': 'X-Custom-Auth',
            'header_prefix': 'custom',
            'custom_header_prefix': 'Token ',
            'url_param_name': 'custom',
            'custom_url_param_name': 'auth_token',
            'user_id': self.user.id
        })

        token._compute_actual_values()
        self.assertEqual(token.actual_header_name, 'X-Custom-Auth')
        self.assertEqual(token.actual_header_prefix, 'Token ')
        self.assertEqual(token.actual_url_param_name, 'auth_token')

    def test_token_generation(self):
        """Test token generation for header type"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Generation',
            'token_type': 'header',
            'header_name': 'Authorization',
            'header_prefix': 'Bearer ',
            'user_id': self.user.id
        })

        # Test token generation
        result = token.btn_regenerate_credentials()

        self.assertIsNotNone(token.static_token)
        # 'ikaa_' + secrets.token_urlsafe(32) = 5 + 43 chars
        self.assertTrue(token.static_token.startswith('ikaa_'))
        self.assertEqual(len(token.static_token), 48)
        self.assertTrue(result)

    def test_curl_generation_header_mode(self):
        """Test cURL command generation in header mode"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test cURL Header',
            'token_type': 'header',
            'header_name': 'X-API-Key',
            'header_prefix': '',
            'static_token': 'test_token_123',
            'test_use_header': True,
            'user_id': self.user.id
        })

        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'http://test.com')
        token.show_password = True

        curl_cmd = token.compute__header_test_curl()

        # The token travels in an environment variable, the header names it.
        self.assertIn('export IKAA_TEST_TOKEN="test_token_123"', curl_cmd)
        self.assertIn('curl --header "X-API-Key: $IKAA_TEST_TOKEN"', curl_cmd)
        self.assertIn('http://test.com' + TOKEN_STATUS_CONTROLLER_URL + '/bearer', curl_cmd)

    def test_curl_generation_url_param_mode(self):
        """Test cURL command generation in URL parameter mode"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test cURL URL',
            'token_type': 'header',
            'url_param_name': 'api_key',
            'actual_url_param_name': 'api_key',
            'static_token': 'test_token_456',
            'test_use_header': False,
            'support_url_param': True,
            'user_id': self.user.id
        })

        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'http://test.com')
        token.show_password = True

        curl_cmd = token.compute__header_test_curl()

        self.assertIn('export IKAA_TEST_TOKEN="test_token_456"', curl_cmd)
        self.assertIn(
            'http://test.com' + TOKEN_STATUS_CONTROLLER_URL + '/bearer?api_key=$IKAA_TEST_TOKEN', curl_cmd)

    def test_python_examples_generation(self):
        """Test Python examples generation for different configurations"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Examples',
            'token_type': 'header',
            'header_name': 'Authorization',
            'header_prefix': 'Bearer ',
            'actual_header_name': 'Authorization',
            'actual_header_prefix': 'Bearer ',
            'static_token': 'test_token_789',
            'support_url_param': True,
            'actual_url_param_name': 'access_token',
            'user_id': self.user.id
        })

        examples = token._generate_header_python_examples('http://test.com')

        # The examples read the token from the environment, never embed it.
        self.assertIn('Bearer Token Authentication', examples)
        self.assertIn("'Authorization': 'Bearer ' + token", examples)
        self.assertIn("'access_token': token", examples)
        self.assertIn('import requests', examples)
        self.assertNotIn('test_token_789', examples)

    def test_gitlab_token_examples(self):
        """Test GitLab-specific examples generation"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test GitLab Examples',
            'token_type': 'header',
            'header_name': 'X-Gitlab-Token',
            'actual_header_name': 'X-Gitlab-Token',
            'header_prefix': '',
            'actual_header_prefix': '',
            'static_token': 'gitlab_token_123',
            'user_id': self.user.id
        })

        examples = token._generate_header_python_examples('http://test.com')

        self.assertIn('GitLab Webhook Authentication', examples)
        self.assertIn("'X-Gitlab-Token': '' + token", examples)
        self.assertNotIn('gitlab_token_123', examples)
        self.assertIn('GitLab webhook secret tokens', examples)

    def test_api_key_examples(self):
        """Test API key examples generation"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test API Key Examples',
            'token_type': 'header',
            'header_name': 'X-API-Key',
            'actual_header_name': 'X-API-Key',
            'header_prefix': '',
            'actual_header_prefix': '',
            'static_token': 'api_key_456',
            'support_url_param': False,
            'user_id': self.user.id
        })

        examples = token._generate_header_python_examples('http://test.com')

        self.assertIn('API Key Authentication', examples)
        self.assertIn("'X-API-Key': '' + token", examples)
        self.assertNotIn('api_key_456', examples)
        self.assertNotIn('URL Parameter', examples)  # Should not include URL param section
        self.assertIn('API keys are often service-specific', examples)

    def test_compute_actual_values_dependencies(self):
        """Test that computed values update when dependencies change"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Dependencies',
            'token_type': 'header',
            'header_name': 'Authorization',
            'header_prefix': 'Bearer ',
            'url_param_name': 'access_token',
            'user_id': self.user.id
        })

        # Initial values
        self.assertEqual(token.actual_header_name, 'Authorization')
        self.assertEqual(token.actual_header_prefix, 'Bearer ')
        self.assertEqual(token.actual_url_param_name, 'access_token')

        # Change to custom values
        token.write({
            'header_name': 'custom',
            'custom_header_name': 'X-Test',
            'header_prefix': 'custom',
            'custom_header_prefix': 'Test ',
            'url_param_name': 'custom',
            'custom_url_param_name': 'test_param'
        })

        # Values should update
        self.assertEqual(token.actual_header_name, 'X-Test')
        self.assertEqual(token.actual_header_prefix, 'Test ')
        self.assertEqual(token.actual_url_param_name, 'test_param')

    def test_no_url_param_support(self):
        """Test behavior when URL parameter support is disabled"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test No URL Param',
            'token_type': 'header',
            'header_name': 'X-API-Key',
            'static_token': 'test_no_url',
            'support_url_param': False,
            'test_use_header': False,
            'user_id': self.user.id
        })

        curl_cmd = token.compute__header_test_curl()
        self.assertIn('URL parameter not supported', curl_cmd)

    def test_token_uniqueness_constraint(self):
        """Test that token uniqueness is enforced across types"""
        # Create first token
        token1 = self.env['ik.api_auth_token'].create({
            'name': 'Test Token 1',
            'token_type': 'header',
            'static_token': 'unique_token_123',
            'user_id': self.user.id
        })

        # Try to create second token with same token but different type
        # This should still work as they're different token types
        token2 = self.env['ik.api_auth_token'].create({
            'name': 'Test Token 2',
            'token_type': 'awssigv4',  # Different type
            'static_token': 'unique_token_123',
            'user_id': self.user.id
        })

        self.assertNotEqual(token1.id, token2.id)

        # But creating another header token with same token should fail
        with self.assertRaises(Exception):  # Unique constraint violation
            self.env['ik.api_auth_token'].create({
                'name': 'Test Token 3',
                'token_type': 'header',
                'static_token': 'unique_token_123',
                'user_id': self.user.id
            })

    def test_default_values(self):
        """Test that default values are properly set"""
        token = self.env['ik.api_auth_token'].create({
            'name': 'Test Defaults',
            'token_type': 'header',
            'user_id': self.user.id
        })

        # Check defaults
        self.assertEqual(token.header_name, 'Authorization')
        self.assertEqual(token.header_prefix, 'Bearer ')
        self.assertEqual(token.url_param_name, 'access_token')
        self.assertTrue(token.support_url_param)

        # Check computed defaults
        token._compute_actual_values()
        self.assertEqual(token.actual_header_name, 'Authorization')
        self.assertEqual(token.actual_header_prefix, 'Bearer ')
        self.assertEqual(token.actual_url_param_name, 'access_token')