# -*- coding: utf-8 -*-
{
    'name': "Inouk API Auth",

    'summary': """ Manages authorization and authentication tokens for Odoo API Controllers.""",

    'description': """
Token-based API authentication system for Odoo controllers.

Features:
* Flexible Header-Based Token authentication
* Bearer Token and X-Gitlab-Token support (legacy compatibility)
* Configurable headers (Authorization, X-API-Key, X-Auth-Token, custom)
* Configurable URL parameters (access_token, api_key, token, custom)
* Service presets for quick setup (OAuth2, GitLab, API Keys)
* HTTPS integrity enforcement
* Token expiration management
* Security audit logging
* New auth='ik_header' authentication method
* Legacy auth='ik_bearer' compatibility
* Legacy @ik_authorize decorator support (deprecated)
* OAuth 2.0 Client Credentials flow (RFC 6749)
* OAuth 2.1 Authorization Code + PKCE (RFC 7636)
* OAuth 2.1 Device Code flow for CLI (RFC 8628)
* Dynamic Client Registration (RFC 7591)
* Authorization Server Metadata (RFC 8414)
""",

    'author': "Cyril MORISSE",
    'website': "https://gitlab.com/cmorisse",

    # Categories can be used to filter modules in modules listing
    # Check https://github.com/odoo/odoo/blob/master/openerp/addons/base/module/module_data.xml
    # for the full list
    'category': 'Inouk',
    'version': '2.1.0',
    'license': 'Other proprietary',  # Elastic License v2.0 — see LICENSE file at repo root
    # any module necessary for this one to work correctly
    'depends': [
        'inouk_core'
    ],

    # always loaded
    'data': [
        'security/ir.model.access.csv',
        #'security/groups.xml',
        #'security/ir_rule.xml',

        # views
        'views/api_auth_token_views.xml',
        'views/oauth_views.xml',
        'views/res_config_settings_views.xml',
        'views/oauth_consent_templates.xml',
        'views/oauth_device_templates.xml',
        'menu.xml',

        # data
        'data/cron.xml',
        'data/cron_oauth21.xml',
        'data/oauth_clients.xml',
    ],
    'demo': [],
    'application': True,
    'auto_install': False,
    'installable': True
}
