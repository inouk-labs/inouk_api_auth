# -*- coding: utf-8 -*-
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

# Every module that imports `request` by name and reads it in an authentication method.
REQUEST_MODULES = (
    'ir_http_extension',
    'ir_http_bearer',
    'ir_http_awssigv4',
    'ir_http_header',
    'ir_http_gitwebhook',
    'ir_http_httpbasic',
)


@contextmanager
def patched_request(mock_request):
    """Bind `mock_request` as the `request` of every ir.http authentication module.

    `request` is a werkzeug proxy that is unbound outside an HTTP request, and each module
    holds its own reference to it, so the replacement is made module by module with an
    explicit `new` (patch never reads the unbound proxy).
    """
    with ExitStack() as stack:
        for module_name in REQUEST_MODULES:
            stack.enter_context(patch(
                f'odoo.addons.inouk_api_auth.models.{module_name}.request', mock_request))
        yield mock_request
