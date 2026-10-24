import re
import hashlib
import hmac
import logging
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, quote

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


class CaseInsensitiveDict:
    """A case-insensitive dictionary wrapper for HTTP headers"""

    def __init__(self, data):
        self._data = {}
        self._original_keys = {}
        for k, v in data.items():
            key_lower = k.lower()
            self._data[key_lower] = v
            self._original_keys[key_lower] = k

    def get(self, key, default=None):
        """Get a value by key (case-insensitive)"""
        return self._data.get(key.lower(), default)

    def items(self):
        """Return items with original key casing"""
        for key_lower, value in self._data.items():
            original_key = self._original_keys[key_lower]
            yield original_key, value

    def __contains__(self, key):
        """Check if key exists (case-insensitive)"""
        return key.lower() in self._data


def generate_aws_credentials():
    """Generate AWS-compatible access key ID and secret access key

    Returns:
        tuple: (access_key_id, secret_access_key)
            - access_key_id: 20 characters starting with 'AKIA'
            - secret_access_key: 40 characters base64-like string
    """
    # Generate Access Key ID (20 chars, starts with AKIA)
    access_key_id = 'AKIA' + ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))

    # Generate Secret Access Key (40 chars, base64-like)
    secret_chars = string.ascii_letters + string.digits + '+/'
    secret_access_key = ''.join(secrets.choice(secret_chars) for _ in range(40))

    return access_key_id, secret_access_key


def generate_signed_curl_command(url, access_key_id, secret_access_key, region='us-east-1', service='execute-api'):
    """Generate a curl command with AWS SigV4 signature

    Args:
        url (str): The URL to sign
        access_key_id (str): AWS access key ID
        secret_access_key (str): AWS secret access key
        region (str): AWS region (default: us-east-1)
        service (str): AWS service name (default: execute-api)

    Returns:
        str: Complete curl command with signed headers
    """
    # Parse URL
    parsed_url = urlparse(url)
    host = parsed_url.netloc
    path = parsed_url.path or '/'
    query = parsed_url.query

    # Create AWS request with minimal headers to match what curl would send
    request = AWSRequest(method='GET', url=url)

    # Only set the essential headers that will be signed
    request.headers['Host'] = host
    # Don't add X-Amz-Date here - let botocore add it

    # Create credentials
    credentials = Credentials(
        access_key=access_key_id,
        secret_key=secret_access_key
    )

    # Create signer and sign request
    signer = SigV4Auth(credentials, service, region)
    signer.add_auth(request)

    # Build curl command - only include the headers that were actually signed
    curl_headers = []
    for header_name, header_value in request.headers.items():
        # Skip headers that curl adds automatically
        if header_name.lower() not in ['user-agent', 'accept', 'accept-encoding']:
            curl_headers.append(f"--header '{header_name}: {header_value}'")

    curl_command = f"curl {' '.join(curl_headers)} '{url}'"

    return curl_command


def _create_canonical_request(method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash):
    """Create the canonical request string according to AWS SigV4 specification"""
    return '\n'.join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])


def _create_string_to_sign(timestamp, credential_scope, canonical_request):
    """Create the string to sign according to AWS SigV4 specification"""
    algorithm = 'AWS4-HMAC-SHA256'
    canonical_request_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()

    return '\n'.join([
        algorithm,
        timestamp,
        credential_scope,
        canonical_request_hash
    ])


def _derive_signing_key(secret_key, date_stamp, region, service):
    """Derive the signing key according to AWS SigV4 specification"""
    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    k_date = sign(('AWS4' + secret_key).encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'aws4_request')

    return k_signing


def _calculate_signature(signing_key, string_to_sign):
    """Calculate the final signature"""
    return hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()


def _normalize_host_header(host_value, scheme):
    """Normalize host header by removing standard ports"""
    if ':' in host_value:
        host, port = host_value.rsplit(':', 1)
        try:
            port_num = int(port)
            # Remove standard ports
            if (scheme == 'https' and port_num == 443) or (scheme == 'http' and port_num == 80):
                return host
            else:
                return host_value  # Keep non-standard ports
        except ValueError:
            return host_value  # Invalid port, keep as-is
    return host_value


def _encode_canonical_uri(path, service=''):
    """Encode canonical URI according to service-specific requirements

    Args:
        path (str): The URL path
        service (str): AWS service name for service-specific encoding

    Returns:
        str: Properly encoded canonical URI
    """
    if not path:
        return '/'

    # S3 doesn't normalize paths - keep them as-is
    if service == 's3':
        return quote(path, safe='/')

    # Most other services require double-encoding for some characters
    # For now, use standard single encoding (works for execute-api)
    return quote(path, safe='/')

    # TODO: Add double-encoding for services that require it
    # if service in ['execute-api'] and needs_double_encoding:
    #     return quote(quote(path, safe=''), safe='/')

    # Default: single encoding
    # return quote(path, safe='/')


def _redact_session_secrets(canonical_request):
    """The canonical request without the values that are credentials: a signed session token
    header or query parameter."""
    lines = []
    for line in canonical_request.split('\n'):
        if line.lower().startswith(('x-amz-security-token:', 'authorization:',
                                          'x-amz-server-side-encryption-customer-key', 'x-amz-copy-source-server-side-encryption-customer-key')):
            line = line.split(':', 1)[0] + ':***'
        lines.append(re.sub(r'(?i)(X-Amz-(?:Security-Token|Signature))=[^&\s]*', r'\1=***', line))
    return '\n'.join(lines)


def validate_aws_signature(headers, method, url, body, access_key_id, secret_access_key, region, service, max_age_seconds=900, debug_logging=False):
    """Validate AWS SigV4 signature by manually recreating the signing process

    Args:
        headers (dict): Request headers
        method (str): HTTP method
        url (str): Request URL
        body (bytes): Request body
        access_key_id (str): Expected access key ID
        secret_access_key (str): Secret access key for validation
        region (str): AWS region
        service (str): AWS service name
        max_age_seconds (int): Maximum age of signature in seconds (default: 15 minutes)
        debug_logging (bool): Write the canonical request and the string to sign at DEBUG (default: False). The signatures are never written.

    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        _logger = logging.getLogger(__name__)

        # Wrap headers in case-insensitive dict
        headers = CaseInsensitiveDict(headers)

        # Check for required headers
        auth_header = headers.get('Authorization', '')
        if not auth_header.startswith('AWS4-HMAC-SHA256'):
            _logger.error("Invalid authorization header format")
            return False

        # Extract date from headers
        date_header = headers.get('X-Amz-Date', '')
        if not date_header:
            _logger.error("Missing X-Amz-Date header")
            return False

        # Parse timestamp and check age
        try:
            request_time = datetime.strptime(date_header, '%Y%m%dT%H%M%SZ')
            request_time = request_time.replace(tzinfo=timezone.utc)
            current_time = datetime.now(timezone.utc)
            age_seconds = (current_time - request_time).total_seconds()

            if debug_logging:
                _logger.info("AWS SigV4 timestamp validation - Request time: %s, Current time: %s, Age: %s seconds",
                            request_time, current_time, age_seconds)

            if age_seconds > max_age_seconds:
                _logger.warning("AWS SigV4 request too old: %s seconds (max: %s)", age_seconds, max_age_seconds)
                return False
        except ValueError as e:
            _logger.error("AWS SigV4 timestamp parsing error: %s", e)
            return False

        # Parse Authorization header components
        try:
            # Extract credential
            credential_part = auth_header.split('Credential=')[1].split(',')[0]
            cred_parts = credential_part.split('/')

            if len(cred_parts) != 5:
                _logger.error("Invalid credential format (%d parts)", len(cred_parts))
                return False

            auth_access_key = cred_parts[0]
            date_stamp = cred_parts[1]
            auth_region = cred_parts[2]
            auth_service = cred_parts[3]

            # Validate credential components
            if auth_access_key != access_key_id:
                _logger.error("Access key mismatch: %s != %s", auth_access_key, access_key_id)
                return False

            if auth_region != region:
                _logger.error("Region mismatch: %s != %s", auth_region, region)
                return False

            if auth_service != service:
                _logger.error("Service mismatch: %s != %s", auth_service, service)
                return False

            # Extract signed headers
            signed_headers_part = auth_header.split('SignedHeaders=')[1].split(',')[0]
            signed_header_names = signed_headers_part.split(';')

            # Extract signature
            signature = auth_header.split('Signature=')[1]

        except (IndexError, AttributeError) as e:
            _logger.error("Error parsing authorization header (%s)", type(e).__name__)
            return False

        # Parse URL components
        parsed_url = urlparse(url)
        canonical_uri = _encode_canonical_uri(parsed_url.path, service)

        # Create canonical query string
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        canonical_querystring = '&'.join(
            f"{quote(k, safe='-_.~')}={quote(v[0] if v else '', safe='-_.~')}"
            for k, v in sorted(query_params.items())
        )

        # Create canonical headers with port normalization
        canonical_headers_dict = {}
        for header_name in signed_header_names:
            header_value = headers.get(header_name)
            if header_value:
                # Handle multi-value headers by joining with commas
                if isinstance(header_value, (list, tuple)):
                    header_value = ','.join(str(v) for v in header_value)

                # Normalize header value (trim whitespace, collapse multiple spaces)
                normalized_value = ' '.join(str(header_value).strip().split())

                # Special handling for Host header - normalize port
                if header_name.lower() == 'host':
                    normalized_value = _normalize_host_header(normalized_value, parsed_url.scheme)

                canonical_headers_dict[header_name.lower()] = normalized_value

        canonical_headers = ''.join(f"{k}:{v}\n" for k, v in sorted(canonical_headers_dict.items()))
        signed_headers = ';'.join(sorted(signed_header_names))

        # Create payload hash
        if body is None:
            body = b''
        payload_hash = hashlib.sha256(body).hexdigest()

        # Create canonical request
        canonical_request = _create_canonical_request(
            method, canonical_uri, canonical_querystring,
            canonical_headers, signed_headers, payload_hash
        )

        # Create string to sign
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = _create_string_to_sign(date_header, credential_scope, canonical_request)

        if debug_logging:
            _logger.debug("AWS SigV4 canonical request:\n%s", _redact_session_secrets(canonical_request))
            _logger.debug("AWS SigV4 string to sign:\n%s", string_to_sign)

        # Derive signing key
        signing_key = _derive_signing_key(secret_access_key, date_stamp, region, service)

        # Calculate expected signature
        expected_signature = _calculate_signature(signing_key, string_to_sign)

        # Secure logging - only log signature validation result and metadata
        signature_matches = signature == expected_signature
        _logger.info("AWS SigV4 validation - Signatures match: %s, Access Key: %s, Region: %s, Service: %s",
                    signature_matches, access_key_id, region, service)

        return signature == expected_signature

    except Exception as e:
        _logger.error("AWS SigV4 validation error: %s", e)
        return False