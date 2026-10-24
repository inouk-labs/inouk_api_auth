import json
import functools
import timeit
import datetime
import re
import pprint
import logging
import warnings
import werkzeug.wrappers
from urllib.parse import urlparse

from odoo import fields
from odoo.http import request, route, Controller
from odoo.exceptions import AccessDenied
from odoo.tools.safe_eval import safe_eval

from .models.log_safety import authorization_scheme, token_fingerprint



_logger = logging.getLogger(__name__)



def ik_authorize(func):
    """ Bearer Token https://tools.ietf.org/html/rfc6750 compatible
    https://stackoverflow.com/questions/22229996/basic-http-and-bearer-token-authentication

    *** DEPRECATED ***
    This decorator is deprecated. Please use auth='ik_bearer' instead.
    Example: @route('/api/endpoint', methods=['GET'], auth='ik_bearer', ...)

    Bearer Token can be passed using:
      - Authorization header
      - access_token URL parameter

    For compatibility with Gitlab WebHook, ik_authorize accepts:
      - X-Gitlab-Token header

    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        # Issue deprecation warning
        warnings.warn(
            "The @ik_authorize decorator is deprecated. "
            "Please migrate to:\n"
            "  - auth='ik_bearer' for standard Bearer authentication\n"
            "  - auth='ik_gitwebhook' for GitLab/GitHub webhooks\n"
            "  - auth='ik_httpbasic' for HTTP Basic authentication\n"
            "  - auth='ik_awssigv4' for AWS Signature v4 authentication",
            DeprecationWarning,
            stacklevel=2
        )

        # Check Sender for token auth
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')
        _logger.debug("HTTP_REFERER received: %s", bool(http_referer))
        requested_url = request.httprequest.url
        _up = urlparse(requested_url)
        _rp = urlparse(http_referer)
        if _up.scheme != 'https' or (http_referer and _rp.scheme != 'https'):
            is_compromised = True
        else:
            is_compromised = False

        token_string = request.httprequest.headers.get('Authorization')
        if token_string:
            token_type = 'bearer'
            token_source = "Authorization header, scheme %s" % authorization_scheme(token_string)
        else:
            token_string = request.httprequest.headers.get('X-Gitlab-Token')
            if token_string:
                token_type = 'xgitlabtoken'
                token_source = "X-Gitlab-Token header"
            else:
                # Odoo 18: use httprequest.args instead of request.params
                token_string = request.httprequest.args.get('access_token')
                if token_string:
                    token_type = 'bearer'
                    token_source = "access_token URL parameter"
                else:
                    raise AccessDenied("Missing required Authorization.")

        if token_string.lower().startswith('bearer '):
            static_token = token_string.split()[1]
        else:
            static_token = token_string.strip()
        _logger.info("Received a credential: %s, fingerprint %s", token_source, token_fingerprint(request.env, static_token))

        token_obj = request.env['ik.api_auth_token'].sudo().search(
            [
                ('static_token', '=', static_token),
                ('token_type', '=', token_type),
                ('is_compromised', '=', False),
                '|',
                    ('expiration_ts', '=', False),
                    ('expiration_ts', '>', fields.Datetime.now()),
            ],
            order='id DESC', 
            limit=1
        )            
        if not token_obj:
            raise AccessDenied("Invalid Access Token.")

        if is_compromised:
            if token_obj.enforce_integrity:
                token_obj.write({
                    'is_compromised': True,
                    'expiration_ts': fields.Datetime.now(),
                    'security_log': ("%s: Token expired by Muppy since it has been received over "
                                    "'http' from %s.\n%s") % (
                                        fields.Datetime.now().isoformat(),
                                        sender_ip,
                                        token_obj.security_log or ''
                                    )
                })
                token_obj.flush_recordset() ; request.env.cr.commit()
                _logger.info("Token %s set as compromised !", token_obj)
                raise AccessDenied("Invalid Access Token.")
            else:
                _logger.warning("Token %s received over unsecure 'http' from %s.", token_obj, sender_ip)
        user_obj = token_obj.user_id
        #request.session.uid = static_token_obj.user_id.id
        #request.uid = static_token_obj.user_id.id
        request.update_env(user=user_obj.id)
        # We must set session_token to validate login
        request.session.session_token = user_obj._compute_session_token(request.session.sid)
        #request.inouk_api_auth_token_id = token_obj.id
        kwargs['token_obj'] = token_obj
        return func(self, *args, **kwargs)
    return wrapper
