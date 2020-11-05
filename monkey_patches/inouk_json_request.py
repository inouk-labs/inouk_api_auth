import os
import sys
import logging
import json
import timeit

import werkzeug
import odoo
from odoo.http import ( WebRequest, Response, AuthenticationError, 
                        SessionExpiredException, serialize_exception, Root)
from odoo.tools import date_utils


_logger = logging.getLogger('IKJSONRequest')

odoo_get_request_method = None

class IKJSONRequest(WebRequest):
    """ Request handler for (non JSON-RPC) JSON requests 
    
    Sucessful request::
      <-- {
            "result": { "res1": "val1" }
          }

    Request producing an error::

      <-- { 
            "error_code": 1, <= HTTP Status Code
            "error_message": "End user error message.",
            "error_data": { "code": "codestring",
                            "debug": "traceback" } },
          }

    IKJSONRequest:
        * are requests with a 'authorization' header. 
        * do not require a JSON value in body
    """
    _request_type = "json"

    def __init__(self, *args):
        self.start_timeit = timeit.default_timer()

        super(IKJSONRequest, self).__init__(*args)

        self.params = {}
        args = self.httprequest.args
        request = self.httprequest.get_data().decode(self.httprequest.charset)
        
        # XSJsonRequest supports empty body.
        if not request:
            request = '{}'

        # Read POST content or POST Form Data named "request"
        try:
            self.jsonrequest = json.loads(request)
        except ValueError:
            msg = 'Invalid JSON data: %r' % (request,)
            _logger.info('%s: %s', self.httprequest.path, msg)
            raise werkzeug.exceptions.BadRequest(msg)

        self.params = dict(self.jsonrequest.get("params", {}))
        self.context = self.params.pop('context', dict(self.session.context))
        self.request_path = self.httprequest.path
        self.request_args = self.httprequest.args.to_dict()
        #_logger.debug("request:%s, url:%s",id(self.httprequest), self.httprequest.url)
        #_logger.debug("request:%s, params:%s",id(self.httprequest), self.request_args)
        #_logger.debug("request:%s, body:%s",id(self.httprequest), json.dumps(self.jsonrequest))
        
    def _json_response(self, result=None, error=None):
        
        if isinstance(result, (Response,  werkzeug.wrappers.Response,)) and error is None:
            return result
            
        response = {}
        if error is not None:
            response.update(error)

        if result is not None:
            response['data'] = result

        body = json.dumps(response, default=date_utils.json_default)
        
        #_logger.debug("request:%s => %s",id(self.httprequest), body)
        full_request_dict = {
            'url': self.httprequest.url,
            'params': self.request_args,
            'request_body': self.jsonrequest,
            'response_body': body,
            'process_time_ms': (timeit.default_timer() - self.start_timeit) * 1000
        }
        _logger.info(full_request_dict)
        return Response(
            body, 
            status=error and error.pop('http_status', 200) or 200,
            headers=[
                ('Content-Type', 'application/json'), 
                ('Content-Length', len(body))
            ]
        )

    def _handle_exception(self, exception):
        """Called within an except block to allow converting exceptions
           to arbitrary responses. Anything returned (except None) will
           be used as response.
           :returns: an object of the form:
            {
                'error_code': 200, <== mostly HTTP status code
                'error_message': "Xsid Server Error",
                'error_data': serialize_exception(exception)
            }           
        """
        try:
            return super(IKJSONRequest, self)._handle_exception(exception)
        except Exception:
            if not isinstance(exception, (odoo.exceptions.Warning, 
                                          AuthenticationError,
                                          SessionExpiredException,
                                          odoo.exceptions.except_orm, 
                                          werkzeug.exceptions.NotFound)):
                _logger.exception("Exception during JSON request handling.")
            error_data = serialize_exception(exception)
            error = {
                'error_code': 200,
                'error_type': exception.__class__.__name__,
                'error_message': error_data.get('message', "XSid Server Error"),
                'error_data': error_data,
                'error_params': self.params,
                'error_request_body': self.jsonrequest,
                'error_request_path': self.request_path,
                'error_request_args': self.request_args,
            }
            if isinstance(exception, werkzeug.exceptions.NotFound):
                error['http_status'] = 404
                error['error_code'] = 404
                error['error_message'] = "404: Not Found"
            if isinstance(exception, AuthenticationError):
                error['http_status'] = 401
                error['error_code'] = 401
                error['error_message'] = exception.__str__()
                del error['error_data']
            if isinstance(exception, SessionExpiredException):
                error['http_status'] = 401
                error['error_code'] = 401
                error['error_message'] = "XSid Session Expired"
                
            return self._json_response(error=error)

    def dispatch(self):
        try:
            result = self._call_function(**self.params)
            return self._json_response(result)

        except Exception as e:
            return self._handle_exception(e)


def inouk_get_request(self, httprequest):
    # deduce type of request
    if ('xsid-static-token' in httprequest.headers or 'authorization' in httprequest.headers) and httprequest.mimetype in ("application/json",):
        return IKJSONRequest(httprequest)
    return odoo_get_request_method(self, httprequest)

def inouk_json_request_patch():
    global odoo_get_request_method
    odoo_get_request_method = Root.get_request
    Root.get_request = inouk_get_request
    _logger.critical("http.py::%s has been patched with %s.", 
                     odoo_get_request_method,
                     Root.get_request)
