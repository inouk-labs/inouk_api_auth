import logging
import secrets
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.exceptions import UserError

from ..controllers.auth import TOKEN_STATUS_CONTROLLER_URL

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('bearer', "Bearer - DEPRECATED"),
]


class InoukAPIAuthToken(models.Model):
    _inherit = 'ik.api_auth_token'

    # Add Bearer to token type selection
    token_type = fields.Selection(
        selection_add=TOKEN_TYPES_LIST,
        ondelete={'bearer': 'cascade'}
    )

    # Identifiable prefix + base64url (better density)
    def generate_credentials_bearer(self):
        """Generate a secure bearer token with identifiable prefix.

        Format: ikaa_<base64url_token>
        - Prefix allows leak detection in logs/repos (like GitHub's ghp_)
        - base64url is more compact than hex (same entropy, fewer chars)
        - 32 bytes = 256 bits of entropy
        """
        prefix = "ikaa_"  # Identifiable prefix for leak scanning
        token = secrets.token_urlsafe(32)  # 256 bits, base64url encoded
        return f"{prefix}{token}"

    @api.model
    def default_get(self, fields_list):
        """Set default values - static_token generation moved to type-specific implementations"""
        result = super().default_get(fields_list)
        if result.get('token_type')=='bearer':
            if 'static_token' in fields_list:
                result['static_token'] = self.generate_credentials_bearer()
        return result


    def regenerate_credentials(self):
        """Regenerate credentials - Bearer token specific implementation"""
        self.ensure_one()
        if self.token_type == 'bearer':
            # Generate standard hex token
            self.static_token = self.generate_credentials_bearer()
            return True
        else:
            return super().regenerate_credentials()

    def compute__bearer_test_curl(self):
        """Generate Bearer token curl command for testing"""
        self.ensure_one()
        if not self.static_token:
            return "# Generate token first"

        # Use unified token status URL for Bearer token
        _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        if not _base_url:
            return "# Configure web.base.url first"

        token_status_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/bearer')

        if self.test_use_header:
            return f'# Set environment variable:\n# export BEARER_TOKEN="your_token_here"\n\ncurl --header "Authorization: Bearer $BEARER_TOKEN" "{token_status_url}"'
        else:
            return f'# Set environment variable:\n# export BEARER_TOKEN="your_token_here"\n\ncurl "{token_status_url}?access_token=$BEARER_TOKEN"'

    def compute__test_curl(self):
        """Override to handle Bearer token cURL generation"""
        for record in self:
            if record.token_type == 'bearer':
                record.test_curl_helper = record.compute__bearer_test_curl()
            else:
                super().compute__test_curl()

    def compute__python_examples(self):
        """Generate Python requests examples for Bearer token authentication"""
        for record in self:
            if record.token_type == 'bearer':
                _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                if not _base_url:
                    record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
                else:
                    bearer_status_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/bearer')
                    title = "Bearer Token Authentication"

                    examples_html = f"""
                    <div style='padding: 10px; font-family: monospace;'>
                    <h3 style='color: #2e7bcf; margin-bottom: 15px;'>{title}</h3>

                    <div style='background: #e3f2fd; padding: 15px; border-radius: 5px; border-left: 4px solid #2196f3; margin-bottom: 15px;'>
                        <strong>📋 Setup Instructions:</strong><br/>
                        1. Copy your token from the form field above<br/>
                        2. Set environment variable:<br/>
                        <code>export BEARER_TOKEN="your_token_here"</code><br/>
                        3. Never commit credentials to version control<br/>
                        4. Use .env files for local development (with python-dotenv)
                    </div>

                    <div style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; margin-bottom: 15px;'>
                        <strong>⚠️ Security Best Practice:</strong>
                        Always use environment variables for credentials. Never hardcode them in your scripts.
                        The examples below use environment variables to keep your credentials secure.
                    </div>

                    <h4 style='color: #666; margin-bottom: 10px;'>Method 1: Header Authentication (Recommended)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import os
import requests

# Load token from environment variable
token = os.environ.get('BEARER_TOKEN')
if not token:
    raise ValueError("Please set BEARER_TOKEN environment variable")

# Unified token status endpoint (JSON response)
url = "{bearer_status_url}"
headers = {{
    'Authorization': f'Bearer {{token}}'
}}

response = requests.get(url, headers=headers)
print(f"Status: {{response.status_code}}")

# JSON response with comprehensive token info
if response.status_code == 200:
    token_info = response.json()
    print("✅ Authentication successful!")
    print(f"Token status: {{token_info['status']}}")
    print(f"Token name: {{token_info['token']['name']}}")
    print(f"User: {{token_info['token']['user']}}")
    if 'expires' in token_info['token']:
        print(f"Expires: {{token_info['token']['expires']}}")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: URL Parameter (Less Secure)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; overflow-x: auto;'><code style='color: #333;'>import os
import requests

# Load token from environment variable
token = os.environ.get('BEARER_TOKEN')
if not token:
    raise ValueError("Please set BEARER_TOKEN environment variable")

# ⚠️  Note: URL parameters are less secure (visible in logs)
url = "{bearer_status_url}"
params = {{
    'access_token': token
}}

response = requests.get(url, params=params)
print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 3: POST Request Example</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4caf50; overflow-x: auto;'><code style='color: #333;'>import os
import requests
import json

# Load token from environment variable
token = os.environ.get('BEARER_TOKEN')
if not token:
    raise ValueError("Please set BEARER_TOKEN environment variable")

# For your actual API endpoints
url = "{_base_url}/your/api/endpoint"
headers = {{
    'Authorization': f'Bearer {{token}}',
    'Content-Type': 'application/json'
}}

data = {{
    'operation': 'example',
    'parameters': {{
        'key1': 'value1',
        'key2': 'value2'
    }}
}}

response = requests.post(url, headers=headers, json=data)
if response.status_code == 200:
    result = response.json()
    print(f"Success: {{result}}")
else:
    print(f"Error: {{response.status_code}} - {{response.text}}")</code></pre>

                    <div style='margin-top: 30px; padding: 15px; background: #e8f5e8; border-radius: 5px; border-left: 4px solid #4caf50;'>
                        <h4 style='color: #2e7d32; margin-bottom: 10px;'>💡 Tips for Production Use</h4>
                        <ul style='color: #2e7d32; margin: 0; padding-left: 20px;'>
                            <li>Always use HTTPS in production</li>
                            <li>Store tokens securely (environment variables, not in code)</li>
                            <li>Set appropriate token expiration dates</li>
                            <li>Monitor token usage in security logs</li>
                            <li>Implement proper error handling</li>
                            <li>Consider rate limiting in your client code</li>
                            <li>Rotate tokens regularly</li>
                            <li>Prefer Authorization header over URL parameters</li>
                        </ul>
                    </div>
                    </div>
                    """
                    record.python_examples = examples_html
            else:
                super().compute__python_examples()