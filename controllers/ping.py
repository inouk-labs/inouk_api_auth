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

from .auth_api import IKAPIAuthException, ik_auth_authorize

_logger = logging.getLogger("inouk_api_auth")


#
# REST API Params management
#
IK_API_AUTH_SETTINGS = {}
 

# Important
# All route() must set save_session=False to prevent Odoo from returning a session_id cookie.
#

class LAPOUGEError(Exception):
    pass

class IKAPIControllerV1(Controller):
    """ This the generic api controller
    """

    @ik_auth_authorize
    @route('/inouk_api_auth/v1/ping', methods=['POST','GET'], type='json', auth='none', csrf=False, save_session=False)
    def ping(self):
        """ This is a test controller. 
        """
        #raise LAPOUGEError("the boss")
        return "Hello World"
    
