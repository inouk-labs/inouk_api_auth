import base64
import logging
import secrets
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.exceptions import UserError

from ..controllers.auth import TOKEN_STATUS_CONTROLLER_URL

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('httpbasicauth', "HTTP Basic Authentication"),
]


class InoukAPIAuthToken(models.Model):
    _inherit = 'ik.api_auth_token'

    # Add HTTP Basic to token type selection
    token_type = fields.Selection(
        selection_add=TOKEN_TYPES_LIST,
        ondelete={'httpbasicauth': 'cascade'}
    )

    # SQL constraints for HTTP Basic auth
    _sql_constraints = [
        ('httpbasicauth_username_uniq',
         "UNIQUE(httpbasicauth_username)",
         "HTTP Basic username must be unique!")
    ]

    # HTTP Basic Authentication specific fields
    httpbasicauth_username = fields.Char(
        string="HTTP Basic Username",
        help="Username for HTTP Basic Authentication"
    )
    httpbasicauth_password = fields.Char(
        string="HTTP Basic Password",
        help="Password for HTTP Basic Authentication"
    )

    def regenerate_credentials(self):
        """Regenerate HTTP Basic credentials inline"""
        self.ensure_one()

        if self.token_type == 'httpbasicauth':
            # Generate username if empty
            if not self.httpbasicauth_username:
                self.httpbasicauth_username = f"user_{secrets.token_hex(8)}"

            # Always generate new password
            self.httpbasicauth_password = secrets.token_hex(16)

            # NO notification - just update the fields
            return True
        else:
            return super().regenerate_credentials()

    def compute__httpbasicauth_test_curl(self):
        """Generate HTTP Basic auth curl command for testing"""
        self.ensure_one()
        if not self.httpbasicauth_username or not self.httpbasicauth_password:
            return "# Generate HTTP Basic credentials first"

        # Use unified token status URL for HTTP Basic auth
        _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        if not _base_url:
            return "# Configure web.base.url first"

        httpbasic_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/httpbasic')

        # Use environment variables for credentials
        return f"# Set environment variables:\nexport IKAA_HTTPBASIC_USERNAME=\"{self.httpbasicauth_username}\"\nexport IKAA_HTTPBASIC_PASSWORD=\"{self.httpbasicauth_password}\"\n\ncurl --user \"$IKAA_HTTPBASIC_USERNAME:$IKAA_HTTPBASIC_PASSWORD\" \"{httpbasic_url}\""

    def compute__test_curl(self):
        """Override to handle HTTP Basic auth cURL generation"""
        for record in self:
            if record.token_type == 'httpbasicauth':
                record.test_curl_helper = record.compute__httpbasicauth_test_curl()
            else:
                super().compute__test_curl()

    def compute__python_examples(self):
        """Generate Python requests examples for HTTP Basic authentication"""
        for record in self:
            if record.token_type == 'httpbasicauth':
                if not record.httpbasicauth_username or not record.httpbasicauth_password:
                    record.python_examples = "<div style='padding: 20px; color: #ff9800;'><i>Generate HTTP Basic credentials first to see examples</i></div>"
                else:
                    _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                    if not _base_url:
                        record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
                        continue

                    username = record.httpbasicauth_username
                    password = record.httpbasicauth_password
                    httpbasic_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/httpbasic')

                    examples_html = f"""
                    <div style='padding: 10px; font-family: monospace;'>
                    <h3 style='color: #2e7bcf; margin-bottom: 15px;'>HTTP Basic Authentication</h3>

                    <div style='background: #e3f2fd; padding: 15px; border-radius: 5px; border-left: 4px solid #2196f3; margin-bottom: 15px;'>
                        <strong>📋 Setup Instructions:</strong><br/>
                        1. Copy your username and password from the form fields above<br/>
                        2. Set environment variables:<br/>
                        <code>export HTTPBASIC_USERNAME="your_username_here"</code><br/>
                        <code>export HTTPBASIC_PASSWORD="your_password_here"</code><br/>
                        3. Never commit credentials to version control<br/>
                        4. Use .env files for local development (with python-dotenv)
                    </div>

                    <div style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; margin-bottom: 15px;'>
                        <strong>⚠️ Security Best Practice:</strong>
                        Always use environment variables for credentials. Never hardcode them in your scripts.
                        The examples below use environment variables to keep your credentials secure.
                    </div>

                    <h4 style='color: #666; margin-bottom: 10px;'>Method 1: Using requests.auth.HTTPBasicAuth</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import os
import requests
from requests.auth import HTTPBasicAuth

# Load credentials from environment variables
username = os.environ.get('HTTPBASIC_USERNAME')
password = os.environ.get('HTTPBASIC_PASSWORD')
if not username or not password:
    raise ValueError("Please set HTTPBASIC_USERNAME and HTTPBASIC_PASSWORD environment variables")

# Unified token status endpoint (JSON response)
url = "{httpbasic_url}"
auth = HTTPBasicAuth(username, password)

response = requests.get(url, auth=auth)
print(f"Status: {{response.status_code}}")

# JSON response with comprehensive token info
if response.status_code == 200:
    token_info = response.json()
    print("✅ HTTP Basic authentication successful!")
    print(f"Token status: {{token_info['status']}}")
    print(f"Token name: {{token_info['token']['name']}}")
    print(f"User: {{token_info['token']['user']}}")
    print(f"Username: {{token_info['auth_method']['username']}}")
    if 'expires' in token_info['token']:
        print(f"Expires: {{token_info['token']['expires']}}")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: Manual Authorization Header</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4caf50; overflow-x: auto;'><code style='color: #333;'>import os
import requests
import base64

# Load credentials from environment variables
username = os.environ.get('HTTPBASIC_USERNAME')
password = os.environ.get('HTTPBASIC_PASSWORD')
if not username or not password:
    raise ValueError("Please set HTTPBASIC_USERNAME and HTTPBASIC_PASSWORD environment variables")

# Manually create Authorization header
credentials = f"{{username}}:{{password}}"
encoded_credentials = base64.b64encode(credentials.encode()).decode()
headers = {{
    'Authorization': f'Basic {{encoded_credentials}}'
}}

# Unified token status endpoint
url = "{httpbasic_url}"
response = requests.get(url, headers=headers)

print(f"Status: {{response.status_code}}")
# JSON response - parse for better output
if response.status_code == 200:
    token_info = response.json()
    print(f"Token status: {{token_info['status']}}")
else:
    print(f"Response: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 3: POST Request with JSON Data</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #9c27b0; overflow-x: auto;'><code style='color: #333;'>import os
import requests
from requests.auth import HTTPBasicAuth

# Load credentials from environment variables
username = os.environ.get('HTTPBASIC_USERNAME')
password = os.environ.get('HTTPBASIC_PASSWORD')
if not username or not password:
    raise ValueError("Please set HTTPBASIC_USERNAME and HTTPBASIC_PASSWORD environment variables")

# Setup authentication
auth = HTTPBasicAuth(username, password)

# Your API endpoint
url = "{_base_url}/your/api/endpoint"
headers = {{
    'Content-Type': 'application/json'
}}

data = {{
    'operation': 'example',
    'parameters': {{
        'key1': 'value1',
        'key2': 'value2'
    }}
}}

response = requests.post(url, auth=auth, headers=headers, json=data)
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
                        </ul>
                    </div>
                    </div>
                    """
                    record.python_examples = examples_html
            else:
                super().compute__python_examples()