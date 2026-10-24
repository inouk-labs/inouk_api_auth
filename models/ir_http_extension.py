# -*- coding: utf-8 -*-
import logging
from urllib.parse import urlparse

from odoo import models, fields
from odoo.http import request

_logger = logging.getLogger(__name__)


class IrHttpExtension(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _check_token_compromised(cls, req, http_referer):
        """Check if the token transmission was compromised (not sent over HTTPS)

        Args:
            req: The current request object
            http_referer: The HTTP referer header value

        Returns:
            bool: True if the connection is compromised (not HTTPS), False if secure
        """
        requested_url = req.httprequest.url
        parsed_url = urlparse(requested_url)

        # Check if current request is not HTTPS
        if parsed_url.scheme != 'https':
            _logger.debug("Request URL is not HTTPS (scheme %s)", parsed_url.scheme)
            return True

        # Check if referer is present and not HTTPS
        if http_referer:
            parsed_referer = urlparse(http_referer)
            if parsed_referer.scheme != 'https':
                _logger.debug("HTTP_REFERER is not HTTPS (scheme %s)", parsed_referer.scheme)
                return True

        return False

    @classmethod
    def _compromise_token(cls, token_obj, sender_ip):
        """Mark a token as compromised due to security violation

        Args:
            token_obj: The token record to mark as compromised
            sender_ip: The IP address that sent the compromised token
        """
        timestamp = fields.Datetime.now().isoformat()
        security_message = (
            f"{timestamp}: Token expired by Muppy since it has been received over "
            f"'http' from {sender_ip}.\n{token_obj.security_log or ''}"
        )

        token_obj.write({
            'is_compromised': True,
            'expiration_ts': fields.Datetime.now(),
            'security_log': security_message
        })

        # Force commit to ensure the token is immediately marked as compromised
        token_obj.flush_recordset()
        request.env.cr.commit()

        _logger.info("Token %s (ID: %s) set as compromised!", token_obj.name, token_obj.id)

    @classmethod
    def _extract_real_ip(cls, headers):
        """Extract the real client IP from headers (priority order)"""
        # 1. Cloudflare connecting IP
        cf_ip = headers.get('CF-Connecting-IP')
        if cf_ip:
            return cf_ip.strip()

        # 2. X-Forwarded-For (first IP in the chain)
        xff = headers.get('X-Forwarded-For')
        if xff:
            # Take the first IP (leftmost) which is the original client
            first_ip = xff.split(',')[0].strip()
            if first_ip:
                return first_ip

        # 3. X-Real-IP (nginx and other proxies)
        x_real_ip = headers.get('X-Real-IP')
        if x_real_ip:
            return x_real_ip.strip()

        # 4. Fallback to REMOTE_ADDR (direct connection or proxy IP)
        return request.httprequest.environ.get('REMOTE_ADDR', 'unknown')

    @classmethod
    def _extract_proxy_info(cls, headers, real_ip):
        """Extract proxy information"""
        direct_ip = request.httprequest.environ.get('REMOTE_ADDR', 'unknown')

        # Determine if we're behind a proxy
        is_behind_proxy = (real_ip != direct_ip and real_ip != 'unknown' and direct_ip != 'unknown')

        proxy_info = {
            'via': None,
            'proxy_chain': [],
            'proxy_type': None
        }

        if is_behind_proxy:
            proxy_info['via'] = direct_ip

            # Determine proxy type
            if headers.get('CF-Connecting-IP'):
                proxy_info['proxy_type'] = 'cloudflare'
            elif headers.get('X-Real-IP'):
                proxy_info['proxy_type'] = 'nginx'
            elif headers.get('X-Forwarded-For'):
                proxy_info['proxy_type'] = 'generic'

            # Build proxy chain from X-Forwarded-For
            xff = headers.get('X-Forwarded-For')
            if xff:
                # Parse the chain: client, proxy1, proxy2, ..., proxyN
                chain = [ip.strip() for ip in xff.split(',') if ip.strip()]
                proxy_info['proxy_chain'] = chain

        return proxy_info

    @classmethod
    def _analyze_request_source(cls):
        """Analyze network source information"""
        headers = request.httprequest.headers

        # Get real client IP
        real_ip = cls._extract_real_ip(headers)

        # Get proxy information
        proxy_info = cls._extract_proxy_info(headers, real_ip)

        return {
            'remote_ip': real_ip,
            'via': proxy_info['via'],
            'proxy_chain': proxy_info['proxy_chain'],
            'proxy_type': proxy_info['proxy_type'],
            'is_https': request.httprequest.is_secure,
            'user_agent': headers.get('User-Agent', 'unknown')[:100],  # Truncate for safety
            'referer': request.httprequest.environ.get('HTTP_REFERER'),
        }

    @classmethod
    def _build_auth_context(cls, token_obj, auth_type, auth_details=None):
        """Build the complete authentication context"""
        if auth_details is None:
            auth_details = {}

        # Get network analysis
        request_source = cls._analyze_request_source()

        return {
            # Authentication data
            'token': token_obj,
            'token_id': token_obj.id,
            'token_name': token_obj.name,
            'token_type': auth_type,
            'user': token_obj.user_id,
            'user_id': token_obj.user_id.id,
            'user_name': token_obj.user_id.name,

            # Security status
            'is_compromised': token_obj.is_compromised,
            'is_expired': token_obj.expiration_ts and token_obj.expiration_ts <= fields.Datetime.now(),
            'enforce_integrity': token_obj.enforce_integrity,
            'authenticated_at': fields.Datetime.now().isoformat(),

            # Auth-specific details
            'auth_details': auth_details,

            # Network/source analysis
            'request_source': request_source,
        }