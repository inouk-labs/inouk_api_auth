import logging
from datetime import datetime, timedelta
from urllib.parse import urljoin

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

from ..controllers.auth import TEST_CONTROLLER_URL
from .log_safety import register_secret_param, token_fingerprint

_logger = logging.getLogger(__name__)


# Base token types - specific types are added via inheritance
TOKEN_TYPES_LIST = [
    ('header', "Header-Based Token"),
]


class InoukAPIAuthToken(models.Model):
    _name = 'ik.api_auth_token'
    _description = "API Auth Token - Inouk"

    name = fields.Char(required=True)
    description = fields.Char()
    user_id = fields.Many2one('res.users', required=True, ondelete='CASCADE')
    token_type = fields.Selection(
        selection=TOKEN_TYPES_LIST,
        string="Type",
        required=True,
        default="header",
        ondelete={'header': 'cascade'}
    )
    static_token = fields.Char(index=True)
    def generate_credentials(self):
        self.ensure_one()
        raise UserError("Don't know how to generate token of type:'%s'")
 
    expiration_ts = fields.Datetime(
        string="Expires on",
        help="You can define a timestamp after which the token will expire. "
    )
    enforce_integrity = fields.Boolean(
        default=True,
        help="When checked, Muppy will expires Token if received over http (not https)."
    )
    is_compromised = fields.Boolean(
        help="Muppy can set tokens as compromised. Eg. they have been sent using http and not https.",
        default=False
    )
    security_log = fields.Text()

    # Show/Hide sensitive credentials
    show_password = fields.Boolean(
        string="Show Credentials",
        default=False,
        store=False,
        inverse="_inverse_show_password",
        help="Toggle to show/hide sensitive credentials (tokens, passwords, secret keys)"
    )
    def _inverse_show_password(self):
        pass

    # Flexible Header Token Configuration (for header type)
    service_preset = fields.Selection([
        ('standard_bearer', 'Standard Bearer (OAuth2/JWT)'),
        ('gitlab_webhook', 'GitLab Webhook'),
        ('github_pat', 'GitHub Personal Access Token'),
        ('api_key', 'API Key (X-API-Key)'),
        ('custom', 'Custom Configuration')
    ], string="Quick Setup", store=False, help="Quick configuration for common services")

    # Header configuration
    header_name = fields.Selection([
        ('Authorization', 'Authorization'),
        ('X-Gitlab-Token', 'X-Gitlab-Token'),
        ('X-API-Key', 'X-API-Key'),
        ('X-Auth-Token', 'X-Auth-Token'),
        ('custom', 'Custom Header')
    ], default='Authorization', help="HTTP header name to use for authentication")

    custom_header_name = fields.Char(
        string="Custom Header Name",
        help="Specify custom header name when 'Custom Header' is selected"
    )

    header_prefix = fields.Selection([
        ('Bearer ', 'Bearer'),
        ('Basic ', 'Basic'),
        ('', 'No Prefix'),
        ('custom', 'Custom Prefix')
    ], default='Bearer ', help="Prefix to add before the token value in the header")

    custom_header_prefix = fields.Char(
        string="Custom Prefix",
        help="Specify custom prefix (include trailing space if needed)"
    )

    # URL parameter configuration
    support_url_param = fields.Boolean(
        string="Allow URL Parameter",
        default=True,
        help="Allow token to be passed as URL parameter (less secure)"
    )

    url_param_name = fields.Selection([
        ('access_token', 'access_token (OAuth2)'),
        ('api_key', 'api_key'),
        ('token', 'token'),
        ('key', 'key'),
        ('custom', 'Custom Parameter')
    ], default='access_token', help="URL parameter name for token")

    custom_url_param_name = fields.Char(
        string="Custom Parameter Name",
        help="Specify custom URL parameter name"
    )

    # Computed actual values used by authentication
    actual_header_name = fields.Char(
        compute='_compute_actual_values',
        store=True,
        help="Actual header name to use (computed from selection or custom)"
    )
    actual_header_prefix = fields.Char(
        compute='_compute_actual_values',
        store=True,
        help="Actual prefix to use (computed from selection or custom)"
    )
    actual_url_param_name = fields.Char(
        compute='_compute_actual_values',
        store=True,
        help="Actual URL parameter name to use (computed from selection or custom)"
    )

    # Type-specific fields are added via inheritance in separate files

    test_use_header = fields.Boolean(
        "Token in header",
        default=True
    )
    hello_url = fields.Char(
        string="Hello URL",
        compute="compute__test_curl",
        help="This is a test cURL that just returns the token used"
    )
    test_curl_helper = fields.Char(
        string="Test cURL Helper",
        compute="compute__test_curl",
        help="This is a test cURL command using environment variables"
    )
    python_examples = fields.Html(
        string="Python Examples",
        compute="compute__python_examples",
        help="Python requests examples for this authentication token"
    )

    def compute__test_curl(self):
        """Base cURL computation - overridden by type-specific implementations"""
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if _base_url:
                record.hello_url = urljoin(
                    _base_url,
                    TEST_CONTROLLER_URL
                )
                # Default fallback - should be overridden by inherited models
                record.test_curl_helper = f"# Generate credentials first for {record.token_type}"
            else:
                record.hello_url = None
                record.test_curl_helper = "# Configure web.base.url first"

    _sql_constraints = [
        ('token_uniq', "UNIQUE(static_token, token_type)", "Token must be unique!")
    ]

    def log_fingerprint(self):
        """The fingerprint the server log shows for this token (see log_safety)."""
        self.ensure_one()
        return token_fingerprint(self.env, self.static_token)

    def _register_url_param_names(self):
        """Mask the URL parameter names of these tokens in the access log."""
        for token_obj in self.sudo():
            if token_obj.token_type == 'header' and token_obj.actual_url_param_name:
                register_secret_param(token_obj.actual_url_param_name)

    def _register_hook(self):
        """A parameter name stored before the server started is masked from the first request."""
        res = super()._register_hook()
        try:
            with self.env.cr.savepoint():
                self.sudo().search([('token_type', '=', 'header')])._register_url_param_names()
        except Exception:  # e.g. the columns are not created yet during an upgrade
            _logger.warning("Could not read the URL parameter names of the header tokens", exc_info=True)
        return res

    @api.model_create_multi
    def create(self, vals_list):
        records = super().create(vals_list)
        records._register_url_param_names()
        return records

    def write(self, vals):
        res = super().write(vals)
        self._register_url_param_names()
        return res

    @api.model
    def default_get(self, fields_list):
        """Set default values - static_token generation moved to type-specific implementations"""
        result = super().default_get(fields_list)
        # static_token defaults are handled by inherited models based on token_type
        return result

    def btn_regenerate_credentials(self):
        """Base regenerate credentials method - overridden by type-specific implementations"""
        self.ensure_one()
        # Default implementation - should be overridden by inherited models
        raise UserError(_("Credential regeneration not implemented for token type: %s") % self.token_type)

    def btn_refresh(self):
        pass

    def btn_restore_token(self):
        self.ensure_one()
        self.restore_token()

    # Type-specific test curl methods moved to inherited files

    # Type-specific compute methods moved to inherited files

    def compute__python_examples(self):
        """Base Python examples computation - overridden by type-specific implementations"""
        for record in self:
            _base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            if not _base_url:
                record.python_examples = "<div style='padding: 20px; color: #666;'><i>Configure web.base.url system parameter to see examples</i></div>"
            else:
                # Default fallback - should be overridden by inherited models
                record.python_examples = f"<div style='padding: 20px; color: #ff9800;'><i>Generate credentials first for {record.token_type}</i></div>"

    @api.onchange('service_preset')
    def _onchange_service_preset(self):
        """Apply preset configurations for quick setup"""
        if self.service_preset and self.token_type == 'header':
            presets = {
                'standard_bearer': {
                    'header_name': 'Authorization',
                    'header_prefix': 'Bearer ',
                    'support_url_param': True,
                    'url_param_name': 'access_token'
                },
                'gitlab_webhook': {
                    'header_name': 'X-Gitlab-Token',
                    'header_prefix': '',
                    'support_url_param': True,
                    'url_param_name': 'access_token'
                },
                'github_pat': {
                    'header_name': 'Authorization',
                    'header_prefix': 'Bearer ',
                    'support_url_param': False,
                    'url_param_name': 'access_token'
                },
                'api_key': {
                    'header_name': 'X-API-Key',
                    'header_prefix': '',
                    'support_url_param': True,
                    'url_param_name': 'api_key'
                }
            }

            if self.service_preset in presets:
                preset_config = presets[self.service_preset]
                for field, value in preset_config.items():
                    setattr(self, field, value)

    @api.depends('header_name', 'custom_header_name',
                 'header_prefix', 'custom_header_prefix',
                 'url_param_name', 'custom_url_param_name')
    def _compute_actual_values(self):
        """Compute actual values based on selections and custom inputs"""
        for record in self:
            # Compute actual header name
            if record.header_name == 'custom':
                record.actual_header_name = record.custom_header_name or ''
            else:
                record.actual_header_name = record.header_name or 'Authorization'

            # Compute actual header prefix
            if record.header_prefix == 'custom':
                record.actual_header_prefix = record.custom_header_prefix or ''
            else:
                record.actual_header_prefix = record.header_prefix or ''

            # Compute actual URL parameter name
            if record.url_param_name == 'custom':
                record.actual_url_param_name = record.custom_url_param_name or 'access_token'
            else:
                record.actual_url_param_name = record.url_param_name or 'access_token'

    def restore_token(self):
        for record in self:
            record.write({
                'is_compromised': False,
                'expiration_ts': None,
                'security_log': "%s: Token re-enabled by %s\n%s" % (
                    fields.Datetime.now().isoformat(),
                    record.env.user.name,
                    record.security_log or ''
                )
            })