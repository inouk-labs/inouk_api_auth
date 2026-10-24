# -*- coding: utf-8 -*-
import logging

from odoo import models, fields
from odoo.http import request
from odoo.exceptions import AccessDenied

_logger = logging.getLogger(__name__)


class IrHttpAwsSigV4(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_ik_awssigv4(cls):
        """Authentication method for AWS Signature Version 4

        This method implements AWS Signature Version 4 authentication as defined in:
        https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html

        The signature must be provided in the Authorization header with AWS4-HMAC-SHA256 algorithm.
        """
        # Get request information
        method = request.httprequest.method
        url = request.httprequest.url
        headers = dict(request.httprequest.headers)
        body = request.httprequest.get_data()

        _logger.info("AWS SigV4 auth - Method: %s, path: %s", method, request.httprequest.path)

        # Check for required headers
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('AWS4-HMAC-SHA256'):
            raise AccessDenied("Missing or invalid AWS4-HMAC-SHA256 Authorization header.")

        # Parse the Authorization header components
        # Format: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=...
        parsed_auth = {'Algorithm': 'AWS4-HMAC-SHA256'}  # Default algorithm

        # Extract each component from the Authorization header
        if 'Credential=' in auth_header:
            parsed_auth['Credential'] = auth_header.split('Credential=')[1].split(',')[0].strip()

        if 'SignedHeaders=' in auth_header:
            parsed_auth['SignedHeaders'] = auth_header.split('SignedHeaders=')[1].split(',')[0].strip()

        if 'Signature=' in auth_header:
            # Signature is the last component, no comma after it
            parsed_auth['Signature'] = auth_header.split('Signature=')[1].strip()

        # Extract access key ID from the Credential component
        try:
            credential_part = parsed_auth.get('Credential', '')
            if not credential_part:
                raise AccessDenied("Missing Credential in Authorization header.")
            access_key_id = credential_part.split('/')[0]
            _logger.info("AWS SigV4 auth - Extracted access key ID: %s", access_key_id)
        except (IndexError, AttributeError):
            raise AccessDenied("Invalid Authorization header format.")

        # Find token in database by access key ID (single search, no validity filters)
        token_obj = request.env['ik.api_auth_token'].sudo().search([
            ('awssigv4_access_key_id', '=', access_key_id),
            ('token_type', '=', 'awssigv4'),
        ], order='id DESC', limit=1)

        # Decision tree based on token status
        if not token_obj:
            _logger.warning("AWS SigV4 authentication failed - no token found for Access Key: %s", access_key_id)
            raise AccessDenied("Invalid AWS Access Key ID.")
        elif token_obj.is_compromised:
            _logger.warning("AWS SigV4 authentication failed - token %s (ID: %s) is compromised. Access Key: %s",
                          token_obj.name, token_obj.id, access_key_id)
            raise AccessDenied("Invalid AWS Access Key ID.")
        elif token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now():
            _logger.warning("AWS SigV4 authentication failed - token %s (ID: %s) expired at %s. Access Key: %s",
                          token_obj.name, token_obj.id, token_obj.expiration_ts, access_key_id)
            raise AccessDenied("Invalid AWS Access Key ID.")

        _logger.info("AWS SigV4 auth - Found token: %s", token_obj.name)

        # Extract region and service from Authorization header
        try:
            credential_parts = credential_part.split('/')
            region = credential_parts[2]
            service = credential_parts[3]
            _logger.info("AWS SigV4 auth - Extracted region: %s, service: %s", region, service)
        except IndexError:
            raise AccessDenied("Invalid credential format in Authorization header.")

        # Validate signature. TODO: make debug_logging configurable via settings.
        # True writes the canonical request and the string to sign at DEBUG to diagnose a
        # refused signature; the signatures themselves are never written.
        debug_logging = False
        is_valid = cls._validate_awssigv4_signature(
            headers=headers,
            method=method,
            url=url,
            body=body,
            access_key_id=access_key_id,
            secret_access_key=token_obj.awssigv4_secret_access_key,
            region=region,
            service=service,
            debug_logging=debug_logging
        )

        if not is_valid:
            raise AccessDenied("Invalid AWS Signature.")

        # Check if token was sent over HTTPS
        sender_ip = request.httprequest.environ.get('REMOTE_ADDR')
        http_referer = request.httprequest.environ.get('HTTP_REFERER')
        is_compromised = cls._check_token_compromised(request, http_referer)

        if is_compromised:
            if token_obj.enforce_integrity:
                cls._compromise_token(token_obj, sender_ip)
                raise AccessDenied("Invalid Access Token.")
            else:
                _logger.warning("AWS SigV4 token %s received over unsecure 'http' from %s.", token_obj, sender_ip)

        # Authenticate the user associated with the token
        user_obj = token_obj.user_id
        request.update_env(user=user_obj.id)

        # Set session token to validate the session
        request.session.session_token = user_obj._compute_session_token(request.session.sid)

        # Build auth details specific to AWS SigV4
        auth_details = {
            'region': region,
            'service': service,
            'access_key_id': token_obj.awssigv4_access_key_id,
            'algorithm': parsed_auth.get('Algorithm', 'AWS4-HMAC-SHA256'),
            'credential_scope': credential_part.split('/', 1)[1] if '/' in credential_part else None
        }

        # Build and store complete auth context
        request.inouk_api_auth = cls._build_auth_context(
            token_obj=token_obj,
            auth_type='awssigv4',
            auth_details=auth_details
        )

        # Keep legacy attributes for backward compatibility
        request.inouk_token_obj = token_obj
        request.awssigv4_region = region
        request.awssigv4_service = service

        _logger.debug("User %s authenticated via AWS SigV4 token %s", user_obj.name, token_obj.name)

    @classmethod
    def _validate_awssigv4_signature(cls, headers, method, url, body, access_key_id, secret_access_key, region, service, debug_logging=False):
        """Validate AWS SigV4 signature using botocore

        Args:
            headers (dict): Request headers
            method (str): HTTP method
            url (str): Request URL
            body (bytes): Request body
            access_key_id (str): AWS access key ID
            secret_access_key (str): AWS secret access key
            region (str): AWS region
            service (str): AWS service name
            debug_logging (bool): Write the canonical request and the string to sign at DEBUG (never the signatures)

        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            from .awssigv4_helper import validate_aws_signature
            return validate_aws_signature(
                headers=headers,
                method=method,
                url=url,
                body=body,
                access_key_id=access_key_id,
                secret_access_key=secret_access_key,
                region=region,
                service=service,
                debug_logging=debug_logging
            )
        except Exception as e:
            _logger.warning("AWS SigV4 signature validation failed (%s)", type(e).__name__)
            return False