import logging
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.exceptions import UserError

from ..controllers.auth import TOKEN_STATUS_CONTROLLER_URL
from .awssigv4_helper import generate_aws_credentials, generate_signed_curl_command

_logger = logging.getLogger(__name__)


TOKEN_TYPES_LIST = [
    ('awssigv4', "AWS Signature V4"),
]

AWSSIGV4_TEST_CURL = """# Set environment variables:
# export AWS_ACCESS_KEY_ID="{_access_key_id}"
# export AWS_SECRET_ACCESS_KEY="{_secret_access_key_id}"

# Note: This requires manual AWS SigV4 signing. Consider using AWS CLI or SDK instead.
# Example with AWS CLI:
aws apigateway test-invoke-method --rest-api-id YOUR_API_ID --resource-id YOUR_RESOURCE_ID --http-method GET"""



class InoukAPIAuthToken(models.Model):
    _inherit = 'ik.api_auth_token'

    # Add AWS SigV4 to token type selection
    token_type = fields.Selection(
        selection_add=TOKEN_TYPES_LIST,
        ondelete={'awssigv4': 'cascade'}
    )

    # AWS SigV4 specific fields
    awssigv4_access_key_id = fields.Char(
        string="AWS Access Key ID",
        help="AWS Access Key ID for Signature Version 4 authentication (format: AKIA...)"
    )
    awssigv4_secret_access_key = fields.Char(
        string="AWS Secret Access Key",
        help="AWS Secret Access Key for Signature Version 4 authentication (40 characters)"
    )

    def regenerate_credentials(self):
        """Regenerate credentials - AWS SigV4 specific implementation"""
        self.ensure_one()

        if self.token_type == 'awssigv4':
            # Generate AWS credentials
            access_key_id, secret_access_key = generate_aws_credentials()
            self.write({
                'awssigv4_access_key_id': access_key_id,
                'awssigv4_secret_access_key': secret_access_key,
            })

            # NO notification - just update the fields
            return True
        else:
            return super().regenerate_credentials()

    def compute__awssigv4_test_curl(self):
        """Generate AWS SigV4 signed curl command for testing"""
        self.ensure_one()
        if not self.awssigv4_access_key_id or not self.awssigv4_secret_access_key:
            return "# Generate AWS keys first"

        # Use unified token status URL for AWS SigV4
        _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
        if not _base_url:
            return "# Configure web.base.url first"

        # Render template with actual credentials
        awssigv4_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/awssigv4')

        # Generate curl command with environment variables
        if self.show_password:
            _access_key_id = self.awssigv4_access_key_id
            _secret_access_key_id = self.awssigv4_secret_access_key       
        else:
            _access_key_id = "your_access_key_here"
            _secret_access_key_id = "your_secret_key_here"

        return AWSSIGV4_TEST_CURL.format(
            _access_key_id=_access_key_id,
            _secret_access_key_id=_secret_access_key_id,
        )

    def compute__test_curl(self):
        """Override to handle AWS SigV4 cURL generation"""
        for record in self:
            if record.token_type == 'awssigv4':
                record.test_curl_helper = record.compute__awssigv4_test_curl()
            else:
                super().compute__test_curl()

    def compute__python_examples(self):
        """Generate Python requests examples for AWS Signature V4 authentication"""
        for record in self:
            if record.token_type == 'awssigv4':
                if not record.awssigv4_access_key_id or not record.awssigv4_secret_access_key:
                    record.python_examples = "<div style='padding: 20px; color: #ff9800;'><i>Generate AWS keys first to see examples</i></div>"
                else:
                    _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
                    if not _base_url:
                        record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
                        continue

                    access_key = record.awssigv4_access_key_id
                    secret_key = record.awssigv4_secret_access_key
                    awssigv4_status_url = urljoin(_base_url, TOKEN_STATUS_CONTROLLER_URL + '/awssigv4')

                    examples_html = f"""
                    <div style='padding: 10px; font-family: monospace;'>
                    <h3 style='color: #2e7bcf; margin-bottom: 15px;'>AWS Signature Version 4 Authentication</h3>

                    <div style='background: #e3f2fd; padding: 15px; border-radius: 5px; border-left: 4px solid #2196f3; margin-bottom: 15px;'>
                        <strong>📋 Setup Instructions:</strong><br/>
                        1. Copy your AWS credentials from the form fields above<br/>
                        2. Set environment variables:<br/>
                        <code>export AWS_ACCESS_KEY_ID="your_access_key_here"</code><br/>
                        <code>export AWS_SECRET_ACCESS_KEY="your_secret_key_here"</code><br/>
                        3. Never commit credentials to version control<br/>
                        4. Use .env files for local development (with python-dotenv)<br/>
                        5. Consider using IAM roles when possible
                    </div>

                    <div style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; margin-bottom: 15px;'>
                        <strong>⚠️ Security Best Practice:</strong>
                        Always use environment variables for AWS credentials. Never hardcode them in your scripts.
                        The examples below use environment variables to keep your credentials secure.
                    </div>

                    <h4 style='color: #666; margin-bottom: 10px;'>Installation Required</h4>
                    <pre style='background: #ffe0b2; padding: 15px; border-radius: 5px; border-left: 4px solid #ff9800; overflow-x: auto;'><code style='color: #333;'># Install required package
pip install requests-aws4auth</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 1: Using requests-aws4auth Library</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #2e7bcf; overflow-x: auto;'><code style='color: #333;'>import os
import requests
from requests_aws4auth import AWS4Auth

# Load AWS credentials from environment variables
access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
if not access_key_id or not secret_access_key:
    raise ValueError("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")

# AWS configuration
region = 'us-east-1'  # You can change this
service = 'execute-api'  # You can change this

# Create auth object
auth = AWS4Auth(access_key_id, secret_access_key, region, service)

# Unified token status endpoint (JSON response)
url = "{awssigv4_status_url}"
response = requests.get(url, auth=auth)

print(f"Status: {{response.status_code}}")

# JSON response with comprehensive token info
if response.status_code == 200:
    token_info = response.json()
    print("✅ AWS SigV4 authentication successful!")
    print(f"Token status: {{token_info['status']}}")
    print(f"Token name: {{token_info['token']['name']}}")
    print(f"User: {{token_info['token']['user']}}")
    print(f"AWS Region: {{token_info['auth_method']['region']}}")
    print(f"AWS Service: {{token_info['auth_method']['service']}}")
    if 'expires' in token_info['token']:
        print(f"Expires: {{token_info['token']['expires']}}")
else:
    print(f"❌ Authentication failed: {{response.text}}")</code></pre>

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 2: POST Request with JSON Data</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #4caf50; overflow-x: auto;'><code style='color: #333;'>import os
import requests
import json
from requests_aws4auth import AWS4Auth

# Load AWS credentials from environment variables
access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
if not access_key_id or not secret_access_key:
    raise ValueError("Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")

# Setup authentication
auth = AWS4Auth(access_key_id, secret_access_key, 'us-east-1', 'execute-api')

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

                    <h4 style='color: #666; margin-bottom: 10px; margin-top: 20px;'>Method 3: Using boto3 (AWS SDK)</h4>
                    <pre style='background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #9c27b0; overflow-x: auto;'><code style='color: #333;'># Alternative: Use AWS SDK (boto3) which handles credentials automatically
import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import requests

# boto3 automatically loads from ENV vars or ~/.aws/credentials
session = boto3.Session()
credentials = session.get_credentials()
region = 'us-east-1'
service = 'execute-api'

# Create signed request
url = "{awssigv4_status_url}"
request = AWSRequest(method='GET', url=url)
SigV4Auth(credentials, service, region).add_auth(request)

# Execute request
response = requests.get(url, headers=dict(request.headers))
print(f"Status: {{response.status_code}}")</code></pre>

                    <div style='margin-top: 30px; padding: 15px; background: #e8f5e8; border-radius: 5px; border-left: 4px solid #4caf50;'>
                        <h4 style='color: #2e7d32; margin-bottom: 10px;'>💡 Tips for Production Use</h4>
                        <ul style='color: #2e7d32; margin: 0; padding-left: 20px;'>
                            <li>Always use HTTPS in production</li>
                            <li>Store AWS credentials securely (environment variables, not in code)</li>
                            <li>Set appropriate token expiration dates</li>
                            <li>Monitor token usage in security logs</li>
                            <li>Use IAM roles when possible instead of access keys</li>
                            <li>Implement proper error handling</li>
                            <li>Consider rate limiting in your client code</li>
                            <li>Rotate credentials regularly</li>
                        </ul>
                    </div>
                    </div>
                    """
                    record.python_examples = examples_html
            else:
                super().compute__python_examples()