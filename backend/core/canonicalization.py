"""
Canonicalization layer — chuẩn hóa tất cả values trước khi so sánh/dedup.
Nếu không có layer này, cùng một host sẽ tạo ra nhiều entities.

V5: Stronger dedup — strip default ports, collapse path segments,
    normalize service keys, endpoint dedup by normalized path.
"""
import re
import socket
from urllib.parse import urlparse, urlencode, parse_qs


# Default ports: stripped from URL netloc during canonicalization
_DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21"}


class Canonicalizer:

    @staticmethod
    def domain(value: str) -> str:
        """Normalize domain về dạng chuẩn"""
        v = value.strip().lower()
        v = v.strip('.')            # bỏ leading + trailing dot
        v = v.removeprefix('www.')  # optional: bỏ www prefix (tuỳ policy)
        # Punycode normalize (xDN)
        try:
            v = v.encode('idna').decode('ascii')
        except (UnicodeError, UnicodeDecodeError):
            pass
        return v

    @staticmethod
    def url(value: str) -> str:
        """Normalize URL — strip default port, collapse path, sort query."""
        raw = value.strip()
        # Ensure scheme
        if not raw.lower().startswith(("http://", "https://", "ftp://")):
            raw = "https://" + raw
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower() or "https"
        host = parsed.hostname or ""
        host = host.lower().strip(".").removeprefix("www.")
        port = parsed.port
        # Strip default port
        if port and str(port) == _DEFAULT_PORTS.get(scheme):
            port = None
        netloc = host if not port else f"{host}:{port}"
        # Collapse path: remove /./  resolve /../  collapse //
        path = _collapse_path(parsed.path) if parsed.path else "/"
        if path == "/":
            path = ""  # root URL — no trailing slash
        else:
            path = path.rstrip("/")
        # Sort query parameters for stable comparison
        query = ""
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            query = urlencode(sorted(qs.items()), doseq=True)
        result = f"{scheme}://{netloc}{path}"
        if query:
            result += f"?{query}"
        return result

    @staticmethod
    def ip(value: str) -> str:
        """Normalize IP address — strips leading zeros, validates format."""
        v = value.strip()
        # Handle ip:port format — extract just the IP
        if ":" in v and not v.startswith("["):
            parts = v.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                v = parts[0]
        # Strip leading zeros per octet before inet_aton (avoid octal interpretation)
        try:
            octets = v.split(".")
            if len(octets) == 4:
                v = ".".join(str(int(o)) for o in octets)
            return socket.inet_ntoa(socket.inet_aton(v))
        except (socket.error, ValueError):
            return v

    @staticmethod
    def email(value: str) -> str:
        """Normalize email"""
        return value.strip().lower()

    @staticmethod
    def service_key(value: str) -> str:
        """Normalize service key (host:port) — canonical IP + port."""
        v = value.strip()
        if ":" in v:
            parts = v.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                host = Canonicalizer.ip(parts[0])
                return f"{host}:{parts[1]}"
        return v.lower()

    @staticmethod
    def service_name(value: str) -> str:
        """Normalize service name"""
        mapping = {
            'http': 'http', 'https': 'https',
            'ssh': 'ssh', 'ftp': 'ftp', 'sftp': 'sftp',
            'smtp': 'smtp', 'smtps': 'smtps',
            'mysql': 'mysql', 'postgresql': 'postgresql', 'postgres': 'postgresql',
            'mssql': 'mssql', 'mongodb': 'mongodb', 'redis': 'redis',
            'rdp': 'rdp', 'vnc': 'vnc', 'smb': 'smb',
        }
        v = value.strip().lower()
        return mapping.get(v, v)

    @staticmethod
    def path(value: str) -> str:
        """Normalize URL path — collapse segments, strip trailing slash."""
        v = value.strip()
        if not v.startswith('/'):
            v = '/' + v
        v = _collapse_path(v)
        if v != "/":
            v = v.rstrip("/")
        return v

    @staticmethod
    def endpoint(value: str) -> str:
        """Normalize endpoint — if full URL, use url(); else use path()."""
        v = value.strip()
        if v.lower().startswith(("http://", "https://")):
            return Canonicalizer.url(v)
        return Canonicalizer.path(v)

    @staticmethod
    def organization(value: str) -> str:
        """Basic org name normalization"""
        v = value.strip().lower()
        for suffix in [', inc', ', ltd', ', llc', ' inc.', ' ltd.', ' corp.', ' corporation']:
            v = v.replace(suffix, '')
        return v.strip()

    @classmethod
    def canonicalize(cls, type_: str, value: str) -> str:
        """Route về đúng normalizer theo type"""
        handlers = {
            'domain': cls.domain,
            'subdomain': cls.domain,
            'url': cls.url,
            'ip_address': cls.ip,
            'ip': cls.ip,
            'email_address': cls.email,
            'email': cls.email,
            'service': cls.service_key,
            'endpoint': cls.endpoint,
            'organization': cls.organization,
        }
        handler = handlers.get(type_, lambda v: v.strip().lower())
        return handler(value)

    @classmethod
    def endpoint_dedup_key(cls, value: str) -> str:
        """Generate dedup key for endpoints — ignores query params and fragment."""
        v = value.strip()
        if v.lower().startswith(("http://", "https://")):
            parsed = urlparse(v)
            host = (parsed.hostname or "").lower().strip(".").removeprefix("www.")
            path = _collapse_path(parsed.path) if parsed.path else "/"
            if path != "/":
                path = path.rstrip("/")
            return f"{host}{path}"
        return cls.path(v)


def _collapse_path(path: str) -> str:
    """Collapse //, /./, /../ in path segments."""
    parts = path.split("/")
    resolved = []
    for p in parts:
        if p == "" or p == ".":
            continue
        if p == ".." and resolved:
            resolved.pop()
        else:
            resolved.append(p)
    return "/" + "/".join(resolved) if resolved else "/"
