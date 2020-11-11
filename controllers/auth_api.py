import sys
import traceback
import json
import functools
import logging
import datetime

import werkzeug
import werkzeug.wrappers
import mohawk

from odoo.http import request, route, Controller, AuthenticationError
from odoo.tools.safe_eval import safe_eval

_logger = logging.getLogger("inouk_api_auth")


class IKAPIAuthException(Exception):
    def __init__(self, error):
         self.error = error
    def __str__(self):
         return repr(self.error)    


def lookup_credentials(client_id):
    """ Called by hawk receiver to retreive token info from token id."""
    auth_token_obj = request.env['ik.api_auth_token'].sudo().search(
        [('token_id', '=', client_id)],
        order='id DESC', 
        limit=1
    )            
    if not auth_token_obj:
        _logger.warning(
            "Authorization failed for Token [%s] from IP:%s. Token does not exists.",
            client_id,
            request.httprequest.environ['REMOTE_ADDR'])
        raise AuthenticationError("Unauthorized")

    if auth_token_obj.token_type != 'hawk':
        _logger.warning(
            "Authorization failed for Token '%s'[%s] from IP:%s. Token Type is wrong.",
            auth_token_obj.name,
            auth_token_obj.token_id,
            request.httprequest.environ['REMOTE_ADDR'])
        raise AuthenticationError("Unauthorized (wt)")

    if auth_token_obj.expiration_ts and auth_token_obj.expiration_ts < datetime.datetime.now():
        _logger.warning(
            "Authorization failed for **Expired** Token '%s'[%s] from IP:%s.",
            auth_token_obj.name,
            auth_token_obj.token_id,
            request.httprequest.environ['REMOTE_ADDR'])
        raise AuthenticationError("Unauthorized (te)")

    IP_to_test = request.httprequest.environ['REMOTE_ADDR']
    if auth_token_obj.allowed_cidrs and not auth_token_obj.check_ip_is_allowed(IP_to_test):
        _logger.warning(
            "Authorization failed for token '%s'[%s]; IP:'%s' is not allowed.",
            auth_token_obj.name,
            auth_token_obj.token_id,
            IP_to_test)
        raise AuthenticationError("Unauthorized (wia)")

    return {
        'id': auth_token_obj.token_id,
        'key': auth_token_obj.token_key,
        'algorithm': 'sha256',
        'ik_api_auth_token': auth_token_obj.id,
        'ik_api_auth_token_uid': auth_token_obj.user_id.id
    }

def ik_auth_authorize(func):
    @functools.wraps(func)
    def auth_wrapper(self, *args, **kwargs):
        auth_header = request.httprequest.headers.get('authorization')
        if auth_header:
            if auth_header[:4].lower() == 'hawk':
                #hawk_dict = werkzeug.http.parse_dict_header(auth_header[5:])
                #_logger.info("url_root=%s", request.httprequest.url_root)
                #_logger.info("path=%s", request.httprequest.path)
                #_logger.info("query_string=%s", request.httprequest.query_string)
                #_logger.info("hawk_dict=%s", hawk_dict)
                # We rebuild URL to various URL encoding
                hawk_url = werkzeug.urls.url_join(request.httprequest.url_root,
                                                  request.httprequest.path)
                hawk_url = "%s?%s" % (
                    hawk_url,
                    request.httprequest.query_string.decode('utf8')
                )
                #_logger.info("hawk_url=%s", hawk_url)
                try:
                    receiver = mohawk.Receiver(
                        lookup_credentials,
                        auth_header,
                        hawk_url,
                        request.httprequest.method,
                        content=request.httprequest.data,
                        content_type=request.httprequest.headers['Content-Type'],
                        seen_nonce=None,  # TODO: Implement
                        accept_untrusted_content=True  # Do not force content hashing
                    )
                except:
                    exception_values = sys.exc_info()
                    _logger.error("\n".join(traceback.format_exception(*exception_values)))
                    raise AuthenticationError("Token Error")

                auth_token_obj = request.env['ik.api_auth_token'].sudo().browse(
                    receiver.resource.credentials['ik_api_auth_token']
                )
                request.uid = request.session.uid = auth_token_obj.user_id.id
                return func(self, *args, **kwargs)

            elif auth_header[:6].lower() == 'bearer':
                auth_token = auth_header.split(' ')[1]
                auth_token_obj = request.env['ik.api_auth_token'].sudo().search(
                    [('token_id', '=', auth_token)],
                    order='id DESC', 
                    limit=1
                )
                if auth_token_obj:
                    if auth_token_obj.expiration_ts and auth_token_obj.expiration_ts < datetime.datetime.now():
                        raise AuthenticationError("Token Expired")
                    
                    IP_to_test = request.httprequest.environ['REMOTE_ADDR']
                    if not auth_token_obj.check_ip_is_allowed(IP_to_test):
                        _logger.warning(
                            "Authorization failed for token '%s'[%s]; IP:'%s' is not allowed.",
                            auth_token_obj.name,
                            auth_token_obj.token_id,
                            IP_to_test)
                        raise AuthenticationError("Unauthorized")

                    request.uid = request.session.uid = auth_token_obj.user_id.id
                    return func(self, *args, **kwargs)

        else:
            raise AuthenticationError("Missing 'authorization' header (Hawk or Bearer) in request.")

        request.uid = request.session.uid = auth_token_obj.user_id.id
        return func(self, *args, **kwargs)
    return auth_wrapper


