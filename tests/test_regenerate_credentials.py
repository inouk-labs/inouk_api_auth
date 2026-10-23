# -*- coding: utf-8 -*-
from odoo.tests.common import TransactionCase, tagged


@tagged('post_install', '-at_install')
class TestRegenerateCredentials(TransactionCase):
    """`regenerate_credentials()` is the business method behind the Regenerate button
    (STD-01, STD-59): code calls it, and each token type overrides it. No demo data."""

    # The fields each token type regenerates, and the extra values its creation needs.
    TYPES = {
        'bearer': (('static_token',), {}),
        'header': (('static_token',), {'header_name': 'Authorization'}),
        'xgitlabtoken': (('static_token',), {}),
        'httpbasicauth': (('httpbasicauth_password',), {}),
        'awssigv4': (('awssigv4_access_key_id', 'awssigv4_secret_access_key'), {}),
        'oauth_client': (('oauth_client_secret',), {}),
    }

    def _token(self, token_type, extra_values):
        return self.env['ik.api_auth_token'].create(dict({
            'name': 'Regenerate %s' % token_type,
            'token_type': token_type,
            'user_id': self.env.user.id,
        }, **extra_values))

    def test_each_type_regenerates_its_credentials(self):
        token_types = dict(self.env['ik.api_auth_token']._fields['token_type'].selection)
        for token_type, (field_names, extra_values) in self.TYPES.items():
            if token_type not in token_types:
                continue
            with self.subTest(token_type=token_type):
                token = self._token(token_type, extra_values)
                before = {name: token[name] for name in field_names}
                self.assertIs(token.regenerate_credentials(), True)
                for name in field_names:
                    self.assertTrue(token[name], "%s: %s is set" % (token_type, name))
                    self.assertNotEqual(token[name], before[name],
                                        "%s: %s is new" % (token_type, name))

    def test_the_button_calls_the_business_method(self):
        token = self._token('awssigv4', {})
        before = token.awssigv4_secret_access_key
        self.assertIs(token.btn_regenerate_credentials(), True)
        self.assertNotEqual(token.awssigv4_secret_access_key, before)
