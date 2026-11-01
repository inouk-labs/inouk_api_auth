from odoo.tests import tagged
from odoo.tests.common import TransactionCase


@tagged('post_install', '-at_install')
class TestCurlHelpers(TransactionCase):
    """The cURL helpers are shell commands to paste: they hold real line breaks."""

    def setUp(self):
        super().setUp()
        self.env['ir.config_parameter'].sudo().set_param('web.base.url', 'https://example.test')
        self.user = self.env.ref('base.user_admin')

    def _assert_real_lines(self, helper):
        self.assertIn('\n', helper)
        self.assertNotIn('\\n', helper)

    def test_xgitlabtoken_helper_breaks_its_lines(self):
        for use_header in (True, False):
            token = self.env['ik.api_auth_token'].create({
                'name': 'GitLab curl helper %s' % use_header,
                'token_type': 'xgitlabtoken',
                'static_token': 'generated-by-the-test-%s' % use_header,
                'user_id': self.user.id,
                'test_use_header': use_header,
            })
            self._assert_real_lines(token.compute__xgitlabtoken_test_curl())
            self._assert_real_lines(token.test_curl_helper)
