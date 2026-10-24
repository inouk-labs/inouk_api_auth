# -*- coding: utf-8 -*-
import base64
import contextlib
import logging
import secrets
from unittest.mock import MagicMock, patch

from odoo.tests.common import HttpCase, TransactionCase, tagged
from odoo.addons.inouk_api_auth.controllers.auth import TOKEN_STATUS_CONTROLLER_URL
from odoo.addons.inouk_api_auth.models.awssigv4_helper import validate_aws_signature
from odoo.addons.inouk_api_auth.models.log_safety import token_fingerprint

from .common import patched_request

HELLO_URL = '/inouk/api_auth/v1/hello'
STATUS_URL = TOKEN_STATUS_CONTROLLER_URL + '/bearer'
AWS_STATUS_URL = TOKEN_STATUS_CONTROLLER_URL + '/awssigv4'
BASIC_STATUS_URL = TOKEN_STATUS_CONTROLLER_URL + '/httpbasic'

# The addon's own log and the access log of the HTTP server, which carries the query string.
CAPTURED_LOGGERS = ('odoo.addons.inouk_api_auth', 'werkzeug')


class _Records(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


@contextlib.contextmanager
def captured_log():
    """The lines written by the addon and by the access log, at DEBUG."""
    handler = _Records()
    saved = []
    for name in CAPTURED_LOGGERS:
        logger = logging.getLogger(name)
        saved.append((logger, logger.level))
        logger.setLevel(logging.DEBUG)
        logger.addHandler(handler)
    try:
        yield handler.lines
    finally:
        for logger, level in saved:
            logger.removeHandler(handler)
            logger.setLevel(level)


class _NoSecretMixin:
    def assert_no_secret(self, lines, secrets_, label):
        self.assertTrue(lines, "%s: nothing was logged, the capture is blind" % label)
        for line in lines:
            for value in secrets_:
                self.assertNotIn(value, line, "%s: a credential is in the log" % label)


@tagged('post_install', '-at_install')
class TestNoSecretInLog(_NoSecretMixin, HttpCase):
    """No credential reaches the server log, at any level, whatever the way it is sent."""

    def setUp(self):
        super().setUp()
        self.api_user = self.env['res.users'].create({
            'name': 'API Auth Log Test User',
            'login': 'api_auth_log_test_user',
            'email': 'api_auth_log_test_user@example.com',
        })
        self.token_value = secrets.token_hex(30)
        self.env['ik.api_auth_token'].create({
            'name': 'Log Test Token',
            'user_id': self.api_user.id,
            'static_token': self.token_value,
            'token_type': 'bearer',
            'enforce_integrity': False,
        })
        self.gitlab_value = secrets.token_hex(30)
        self.env['ik.api_auth_token'].create({
            'name': 'Log Test GitLab Token',
            'user_id': self.api_user.id,
            'static_token': self.gitlab_value,
            'token_type': 'xgitlabtoken',
            'enforce_integrity': False,
        })

    def _call_and_check(self, url, headers, value, label, status=200):
        with captured_log() as lines:
            response = self.url_open(url, headers=headers)
        self.assertEqual(response.status_code, status, label)
        self.assert_no_secret(lines, [value], label)
        return lines

    def test_authorization_header(self):
        self._call_and_check(STATUS_URL, {'Authorization': 'Bearer ' + self.token_value},
                             self.token_value, 'status, Authorization header')

    def test_authorization_header_decorator(self):
        self._call_and_check(HELLO_URL, {'Authorization': 'Bearer ' + self.token_value},
                             self.token_value, 'hello, Authorization header')

    def test_gitlab_header(self):
        self._call_and_check(STATUS_URL, {'X-Gitlab-Token': self.gitlab_value},
                             self.gitlab_value, 'status, X-Gitlab-Token header')

    def test_gitlab_header_decorator(self):
        self._call_and_check(HELLO_URL, {'X-Gitlab-Token': self.gitlab_value},
                             self.gitlab_value, 'hello, X-Gitlab-Token header')

    def test_url_parameter(self):
        lines = self._call_and_check(STATUS_URL + '?access_token=' + self.token_value, {},
                                     self.token_value, 'status, access_token parameter')
        # the access line of the HTTP server is written, with the value masked
        self.assertTrue(any('access_token=***' in line for line in lines), lines)

    def test_url_parameter_hello(self):
        self._call_and_check(HELLO_URL + '?access_token=' + self.token_value, {},
                             self.token_value, 'hello, access_token parameter')

    def test_a_refusal_is_diagnosable(self):
        """The log names the scheme and the fingerprint of a refused credential."""
        wrong = secrets.token_hex(30)
        with captured_log() as lines:
            self.url_open(STATUS_URL, headers={'Authorization': 'Bearer ' + wrong})
        self.assert_no_secret(lines, [wrong], 'refused credential')
        self.assertTrue(any('scheme Bearer' in line and token_fingerprint(self.env, wrong) in line
                            for line in lines), lines)

    def test_http_basic(self):
        user, password = 'user-' + secrets.token_hex(6), secrets.token_hex(20)
        self.env['ik.api_auth_token'].create({
            'name': 'Log Test Basic Token',
            'user_id': self.api_user.id,
            'token_type': 'httpbasicauth',
            'httpbasicauth_username': user,
            'httpbasicauth_password': password,
            'enforce_integrity': False,
        })
        for label, decoded in (('regular', '%s:%s' % (user, password)),
                               # user and password swapped by the client: the password is the user name
                               ('swapped', '%s:%s' % (password, user)),
                               ('wrong password', '%s:%s' % (user, secrets.token_hex(20)))):
            header = 'Basic ' + base64.b64encode(decoded.encode()).decode()
            with captured_log() as lines:
                self.url_open(BASIC_STATUS_URL, headers={'Authorization': header})
            self.assert_no_secret(lines, [password, header.split()[1]] + decoded.split(':'), 'basic ' + label)

    def test_aws_sigv4(self):
        access_key, secret_key = 'AKIA' + secrets.token_hex(8).upper(), secrets.token_hex(20)
        signature = secrets.token_hex(32)
        self.env['ik.api_auth_token'].create({
            'name': 'Log Test AWS Token',
            'user_id': self.api_user.id,
            'token_type': 'awssigv4',
            'awssigv4_access_key_id': access_key,
            'awssigv4_secret_access_key': secret_key,
            'enforce_integrity': False,
        })
        header = ('AWS4-HMAC-SHA256 Credential=%s/20260101/us-east-1/s3/aws4_request, '
                  'SignedHeaders=host;x-amz-date, Signature=%s' % (access_key, signature))
        with captured_log() as lines:
            self.url_open(AWS_STATUS_URL, headers={'Authorization': header, 'X-Amz-Date': '20260101T000000Z'})
        self.assert_no_secret(lines, [secret_key, signature], 'aws status')

    def test_aws_sigv4_debug_logging(self):
        """The debug mode of the helper writes the canonical request, never a signature."""
        signature, token = secrets.token_hex(32), secrets.token_hex(20)
        from datetime import datetime, timezone
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        header = ('AWS4-HMAC-SHA256 Credential=AKIATEST/%s/us-east-1/s3/aws4_request, '
                  'SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=%s' % (stamp[:8], signature))
        headers = {'Host': 'example.test', 'X-Amz-Date': stamp, 'X-Amz-Security-Token': token,
                   'Authorization': header}
        with captured_log() as lines:
            result = validate_aws_signature(headers, 'GET', 'https://example.test/bucket', b'',
                                            'AKIATEST', secrets.token_hex(20), 'us-east-1', 's3',
                                            debug_logging=True)
        self.assertFalse(result)
        self.assert_no_secret(lines, [signature, token], 'aws debug')
        self.assertTrue(any('canonical request' in line for line in lines), lines)
        self.assertFalse(any('Expected signature' in line for line in lines), lines)

    def test_oauth_authorization_code(self):
        user = self.env['res.users'].create({
            'name': 'OAuth Log Test User',
            'login': 'oauth_log_test_user',
            'password': secrets.token_hex(12),
        })
        password = secrets.token_hex(12)
        user.password = password
        client = self.env['ik.oauth_client_registration'].create({
            'client_name': 'Log Test Client',
            'redirect_uris': 'https://example.com/callback',
        })
        self.authenticate(user.login, password)
        with captured_log() as lines:
            response = self.url_open('/oauth/authorize', data={
                'response_type': 'code', 'client_id': client.client_id,
                'redirect_uri': 'https://example.com/callback', 'decision': 'allow',
                'code_challenge': 'x' * 43, 'code_challenge_method': 'S256',
            })
        self.assertEqual(response.status_code, 200)
        codes = self.env['ik.oauth_authorization_code'].sudo().search([('client_registration_id', '=', client.id)])
        self.assertEqual(len(codes), 1, "the authorization code was not issued")
        self.assert_no_secret(lines, [codes.code], 'oauth authorize')


@tagged('post_install', '-at_install')
class TestNoSecretInLogHeaderTokens(_NoSecretMixin, TransactionCase):
    """The configurable header tokens (ir_http_header)."""

    def setUp(self):
        super().setUp()
        self.user = self.env.ref('base.user_admin')
        self.mock_request = MagicMock()
        request_patch = patched_request(self.mock_request)
        request_patch.__enter__()
        self.addCleanup(request_patch.__exit__, None, None, None)
        self.value = secrets.token_hex(20)
        self.env['ik.api_auth_token'].create({
            'name': 'Header Log Test Token',
            'token_type': 'header',
            'static_token': self.value,
            'header_name': 'X-API-Key',
            'header_prefix': 'Basic ',
            'actual_header_name': 'X-API-Key',
            'actual_header_prefix': 'Basic ',
            'support_url_param': True,
            'url_param_name': 'api_key',
            'actual_url_param_name': 'api_key',
            'user_id': self.user.id,
        })

    def _authenticate(self, headers, args=None):
        request = self.mock_request
        request.httprequest.environ = {'REMOTE_ADDR': '127.0.0.1'}
        request.httprequest.headers = headers
        request.httprequest.args = args or {}
        request.params = {}
        request.env = self.env
        request.session = MagicMock(sid='test-session-sid')
        with patch.object(self.env.registry['ir.http'], '_check_token_compromised', return_value=False), \
             patch.object(self.env.registry['ir.http'], '_build_auth_context', return_value={}), \
             captured_log() as lines:
            try:
                self.env['ir.http']._auth_method_ik_header()
            except Exception:  # a refusal is the point of some cases
                pass
        return lines

    def test_custom_header(self):
        lines = self._authenticate({'X-API-Key': 'Basic ' + self.value})
        self.assert_no_secret(lines, [self.value], 'custom header')
        self.assertTrue(any(token_fingerprint(self.env, self.value) in line for line in lines), lines)

    def test_custom_header_with_a_wrong_prefix(self):
        lines = self._authenticate({'X-API-Key': 'Bearer ' + self.value})
        self.assert_no_secret(lines, [self.value], 'custom header, wrong prefix')
        self.assertTrue(any('expected prefix' in line for line in lines), lines)

    def test_custom_url_parameter(self):
        lines = self._authenticate({}, args={'api_key': self.value})
        self.assert_no_secret(lines, [self.value], 'custom url parameter')


@tagged('post_install', '-at_install')
class TestSecretQueryFilter(TransactionCase):
    """The access log filter, on the record itself."""

    def _filtered_line(self, message):
        return self._filtered(message)

    def _filtered(self, message):
        from odoo.addons.inouk_api_auth.models.log_safety import SecretQueryFilter
        record = logging.LogRecord('werkzeug', logging.INFO, __file__, 1, message, (), None)
        SecretQueryFilter().filter(record)
        return record.getMessage()

    def test_masks_secret_parameters(self):
        value = secrets.token_hex(10)
        for query in ('access_token=%s', 'a=1&access_token=%s&b=2', 'access%%5Ftoken=%s', 'ACCESS_TOKEN=%s'):
            line = self._filtered('127.0.0.1 - - "GET /x?' + (query % value) + ' HTTP/1.1" 200 -')
            self.assertNotIn(value, line, query)
        self.assertIn('b=2', self._filtered('"GET /x?access_token=%s&b=2 HTTP/1.1"' % value))

    def test_masks_a_value_holding_quotes(self):
        for raw in ("ab%27cd", "ab'cd", 'ab"cd', "ab'cd'ef"):
            line = self._filtered('"GET /x?access_token=%s&b=2 HTTP/1.1" 200 -' % raw)
            self.assertNotIn('cd', line, raw)
            self.assertIn('b=2', line)

    def test_masks_a_custom_name_in_mixed_case(self):
        from odoo.addons.inouk_api_auth.models import log_safety
        self.addCleanup(log_safety._SECRET_PARAMS.discard, 'apikeymixed')
        log_safety.register_secret_param('apiKeyMixed')
        self.assertNotIn('zzz', self._filtered('"GET /x?apiKeyMixed=zzz HTTP/1.1"'))
        self.assertNotIn('zzz', self._filtered('"GET /x?APIKEYMIXED=zzz HTTP/1.1"'))

    def test_filter_is_on_both_access_loggers_once(self):
        from odoo.addons.inouk_api_auth.models import log_safety
        log_safety.install_access_log_filters()
        for name in ('werkzeug', 'longpolling'):
            ours = [f for f in logging.getLogger(name).filters if getattr(f, 'ik_api_auth_filter', False)]
            self.assertEqual(len(ours), 1, name)
        value = secrets.token_hex(10)
        handler = _Records()
        logger = logging.getLogger('longpolling')
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        level = logger.level
        logger.setLevel(logging.INFO)
        self.addCleanup(logger.setLevel, level)
        logger.info('"GET /x?access_token=%s HTTP/1.1" 200', value)
        self.assertEqual(len(handler.lines), 1)
        self.assertNotIn(value, handler.lines[0])

    def test_leaves_other_parameters_alone(self):
        self.assertEqual(self._filtered('"GET /x?a=1&page=2 HTTP/1.1" 200 -'), '"GET /x?a=1&page=2 HTTP/1.1" 200 -')

    def test_scheme_whitelist(self):
        from odoo.addons.inouk_api_auth.models.log_safety import authorization_scheme
        self.assertEqual(authorization_scheme('Bearer abc'), 'Bearer')
        self.assertEqual(authorization_scheme('aws4-hmac-sha256 Credential=x'), 'AWS4-HMAC-SHA256')
        self.assertEqual(authorization_scheme('s3cretvalue more'), 'unknown')
        self.assertEqual(authorization_scheme('s3cretvalue'), 'unknown')

    def test_fingerprint_is_keyed(self):
        import hashlib
        value = secrets.token_hex(10)
        fingerprint = token_fingerprint(self.env, value)
        self.assertRegex(fingerprint, r'^[0-9a-f]{8}$')
        self.assertNotEqual(fingerprint, hashlib.sha256(value.encode()).hexdigest()[:8])
        self.assertEqual(fingerprint, token_fingerprint(self.env, value))
        token = self.env['ik.api_auth_token'].create({
            'name': 'Fingerprint Test Token', 'token_type': 'bearer', 'static_token': value,
            'user_id': self.env.ref('base.user_admin').id,
        })
        self.assertEqual(token.log_fingerprint(), fingerprint)

    def test_url_parameter_names_are_registered_at_load(self):
        from odoo.addons.inouk_api_auth.models import log_safety
        name = 'ik_k_' + secrets.token_hex(4)
        value = secrets.token_hex(10)
        self.env['ik.api_auth_token'].create({
            'name': 'Param Name Test Token', 'token_type': 'header', 'static_token': secrets.token_hex(10),
            'header_name': 'X-API-Key', 'header_prefix': '', 'support_url_param': True,
            'url_param_name': 'custom', 'custom_url_param_name': name,
            'user_id': self.env.ref('base.user_admin').id,
        })
        self.addCleanup(log_safety._SECRET_PARAMS.discard, name)
        # a freshly started process knows no custom name
        log_safety._SECRET_PARAMS.discard(name)
        self.assertIn(value, self._filtered_line('"GET /x?%s=%s HTTP/1.1"' % (name, value)))
        self.env['ik.api_auth_token']._register_hook()
        self.assertNotIn(value, self._filtered_line('"GET /x?%s=%s HTTP/1.1"' % (name, value)))
