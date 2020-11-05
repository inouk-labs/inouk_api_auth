import logging
import secrets
from datetime import datetime, timedelta

from odoo import api, fields, models, _
from odoo.tools import DEFAULT_SERVER_DATETIME_FORMAT, float_compare
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)


TOKEN_TYPE_CHOICES = [
    ('bearer', "Bearer"),
    ('hawk', "Hawk"),
]


class IKAPIAuthToken(models.Model):
    _name = 'ik.api_auth_token'
    _description = "API Authorization Token (Inouk)"
    
    name = fields.Char(required=True)
    token_type = fields.Selection(TOKEN_TYPE_CHOICES, string="Type", default='hawk')
    user_id = fields.Many2one('res.users', required=True)
    description = fields.Char()
    token_id = fields.Char("Token", help="'Bearer' token or 'Hawk' token id", required=True, index=True)
    token_key = fields.Char()
    allowed_cidrs = fields.Text(
        "Allowed CIDRs/IPs", 
        help="Enter allowed IP / CIDR ; separated with new line (one per line). You can use comment after the CIDR. eg. 8.8.8.8  # Google DNS"
    )
    expiration_ts = fields.Datetime("Expires at")

    @api.onchange('token_type')
    def onchange_token_type(self):
        if self.token_type == 'hawk':
            self.token_key = secrets.token_hex(60)
        else:
            self.token_key = None

    @api.model
    def default_get(self, fields_list):
        result = super(IKAPIAuthToken, self).default_get(fields_list)
        if 'token_id' in fields_list:
            result['token_id'] = secrets.token_hex(30)
        if 'token_key' in fields_list:
            if result['token_type']=='hawk':
                result['token_key'] = secrets.token_hex(60)
            else:
                result['token_key'] = None
        return result
    
    def check_ip_is_allowed(self, ip):
        self.ensure_one()
        networks = [ a_line.split('#')[0].strip() for a_line in self.allowed_cidrs.splitlines()]
        ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
        for net in networks:
            if not '/' in net:
                net = "%s/32" % net
            netstr, bits = net.split('/')
            netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            if (ipaddr & mask) == (netaddr & mask):
                return True
        return False

    def btn_generate_token(self):
        self.ensure_one()
        if self.token_type =='hawk':
            self.token_id = secrets.token_hex(30)
            self.token_key = secrets.token_hex(60)
        else:  # Bearer
            self.token_id = secrets.token_hex(60)
            self.token_key = None
    
    _sql_constraints = [
        ('token_uniq', "UNIQUE(token_id)", "Token must be unique!")
    ]
    