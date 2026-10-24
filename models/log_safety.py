# -*- coding: utf-8 -*-
"""What the addon may write about a credential in the server log.

A credential is never written, whole or in part. To diagnose a refusal the log carries, for a
bearer token, a header token or a URL parameter, the authentication scheme where there is one and
a fingerprint (the first 8 hexadecimal characters of the HMAC-SHA256 of the credential, keyed by
the `database.secret` of the database): two requests carrying the same credential show the same
fingerprint, which cannot be guessed offline from a weak credential. HTTP Basic and AWS SigV4
write no fingerprint; a refusal there names the token once it is resolved. An operator computes the fingerprint of a token from an Odoo shell of the database with
`token.log_fingerprint()`, or `token_fingerprint(env, value)` for a value.

The module also installs a filter on the `werkzeug` logger and on the `longpolling` logger (the
access lines of the gevent server), which write every request with its query string.
"""
import hashlib
import hmac
import logging
import re
import secrets
from urllib.parse import unquote_plus

# Query parameters that carry a secret in this addon. The header-based tokens may name their
# own URL parameter: `register_secret_param()` adds it when a request reads it.
_SECRET_PARAMS = {'access_token', 'code', 'client_secret', 'refresh_token', 'device_code',
                  'api_key'}

_KNOWN_SCHEMES = {'bearer': 'Bearer', 'basic': 'Basic', 'token': 'Token', 'digest': 'Digest',
                  'negotiate': 'Negotiate', 'aws4-hmac-sha256': 'AWS4-HMAC-SHA256'}
_QUERY_PARAM_RE = re.compile(r'(?i)([?&;])([^=&;\s"\']+)=([^&\s]*)')


_FINGERPRINT_KEYS = {}  # database name -> key, read once per process


def _fingerprint_key(env):
    dbname = env.cr.dbname
    key = _FINGERPRINT_KEYS.get(dbname)
    if key is None:
        secret = env['ir.config_parameter'].sudo().get_param('database.secret')
        # Without a secret the key is random for the life of the process: never an unkeyed hash.
        key = _FINGERPRINT_KEYS[dbname] = (secret or secrets.token_hex(32)).encode('utf-8')
    return key


def token_fingerprint(env, value):
    """First 8 hexadecimal characters of the HMAC-SHA256 of `value`, keyed by `database.secret`."""
    return hmac.new(_fingerprint_key(env), (value or '').encode('utf-8', 'replace'),
                    hashlib.sha256).hexdigest()[:8]


def authorization_scheme(header_value):
    """The word before the first space of an Authorization header ('Bearer', 'Basic', ...).

    Only the well-known schemes are named; any other first word answers 'unknown', since it
    may be a credential sent without a scheme.
    """
    word, sep, _rest = (header_value or '').strip().partition(' ')
    return _KNOWN_SCHEMES.get(word.lower(), 'unknown') if sep else 'unknown'


def register_secret_param(name):
    """Mask the value of the query parameter `name` in the access log from now on."""
    if name:
        _SECRET_PARAMS.add(name.lower())  # mask() compares the decoded name in lower case


def redact_query_secrets(text):
    """`text` with the value of every secret query parameter replaced by '***'."""
    if not text or '=' not in text:
        return text

    def mask(match):
        # the name is compared decoded: the server decodes it too ('access%5Ftoken')
        if unquote_plus(match.group(2)).lower() in _SECRET_PARAMS:
            return '%s%s=***' % (match.group(1), match.group(2))
        return match.group(0)

    return _QUERY_PARAM_RE.sub(mask, text)


class SecretQueryFilter(logging.Filter):
    """Masks the secret query parameters in the message of a log record."""
    ik_api_auth_filter = True

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:  # a malformed record is left to the logging machinery
            return True
        redacted = redact_query_secrets(message)
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


ACCESS_LOG_LOGGERS = ('werkzeug', 'longpolling')


def install_access_log_filters():
    """Put one SecretQueryFilter on each access log logger; a reload replaces the previous one."""
    for name in ACCESS_LOG_LOGGERS:
        access_logger = logging.getLogger(name)
        for existing in list(access_logger.filters):
            if getattr(existing, 'ik_api_auth_filter', False):
                access_logger.removeFilter(existing)
        access_logger.addFilter(SecretQueryFilter())


install_access_log_filters()
