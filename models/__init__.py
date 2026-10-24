from . import log_safety  # Import first: installs the access log filters
from . import json_plain_patch  # Import first to apply monkey-patch
from . import api_auth_token
from . import api_auth_token__header  # New unified header implementation
from . import api_auth_token__bearer  # Keep for backward compatibility
from . import api_auth_token__xgitlabtoken  # Keep for backward compatibility
from . import api_auth_token__awssigv4
from . import api_auth_token__httpbasicauth
from . import api_auth_token__oauth_client
from . import api_auth_token__oauth21  # OAuth 2.1 Authorization Code flow fields

# OAuth 2.1 models (must be after api_auth_token for inheritance)
from . import oauth_client_registration  # OAuth 2.1 client registration (RFC 7591)
from . import oauth_authorization_code  # OAuth 2.1 authorization codes
from . import oauth_refresh_token  # OAuth 2.1 refresh tokens
from . import oauth_device_code  # OAuth 2.1 Device Code flow (RFC 8628)

from . import ir_http_extension
from . import ir_http_header  # New unified header authentication
from . import ir_http_bearer  # Keep for backward compatibility
from . import ir_http_gitwebhook  # New unified Git webhook authentication
from . import ir_http_awssigv4
from . import ir_http_httpbasic
from . import res_config_settings