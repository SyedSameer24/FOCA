"""Web technology stack and HTTP security header analyzer."""

import logging
from typing import Optional
import requests

from foca_core.models import TechStackResult

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
]


class TechStackAnalyzer:
    """Analyzes server response headers, cookies, and security posture."""

    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def __init__(self, user_agent: Optional[str] = None) -> None:
        """Initialize analyzer with optional user agent string."""
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

    def analyze(self, domain: str, timeout: int = 10) -> TechStackResult:
        """Probe web endpoints on domain, inspect headers, and detect technologies."""
        clean_domain = self._normalize_domain(domain)
        default_sec_headers = {hdr: False for hdr in SECURITY_HEADERS}

        if not clean_domain:
            return TechStackResult(
                domain=domain,
                status_code=0,
                security_headers=default_sec_headers,
                detected_technologies=[],
            )

        response: Optional[requests.Response] = None
        headers = {"User-Agent": self.user_agent}

        # Try HTTPS first, fallback to HTTP
        for scheme in ("https://", "http://"):
            url = f"{scheme}{clean_domain}"
            try:
                resp = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=True,
                )
                response = resp
                break
            except requests.exceptions.SSLError:
                # Retry HTTPS with verify=False before falling back to HTTP
                if scheme.startswith("https"):
                    try:
                        resp = requests.get(
                            url,
                            headers=headers,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=False,
                        )
                        response = resp
                        break
                    except Exception:
                        pass
            except requests.RequestException as req_err:
                logger.debug("Failed connecting to %s: %s", url, str(req_err))
            except Exception as e:
                logger.debug("Unexpected error probing %s: %s", url, str(e))

        if response is None:
            return TechStackResult(
                domain=clean_domain,
                server_banner=None,
                powered_by=None,
                status_code=0,
                security_headers=default_sec_headers,
                detected_technologies=[],
            )

        resp_headers = response.headers
        server_banner = resp_headers.get("Server")
        powered_by = resp_headers.get("X-Powered-By")
        status_code = response.status_code

        # Check security headers
        lower_headers = {k.lower(): v for k, v in resp_headers.items()}
        security_headers = {
            hdr: (hdr.lower() in lower_headers and bool(lower_headers[hdr.lower()]))
            for hdr in SECURITY_HEADERS
        }

        # Technology detection
        detected = self._detect_technologies(
            server_banner=server_banner,
            powered_by=powered_by,
            headers=lower_headers,
            cookies=response.cookies,
        )

        return TechStackResult(
            domain=clean_domain,
            server_banner=server_banner,
            powered_by=powered_by,
            status_code=status_code,
            security_headers=security_headers,
            detected_technologies=sorted(detected),
        )

    def _detect_technologies(
        self,
        server_banner: Optional[str],
        powered_by: Optional[str],
        headers: dict[str, str],
        cookies: requests.cookies.RequestsCookieJar,
    ) -> list[str]:
        """Infer underlying technology stack from HTTP headers and cookies."""
        technologies: set[str] = set()

        server_lower = (server_banner or "").lower()
        powered_lower = (powered_by or "").lower()
        cookie_names = {c.name.lower() for c in cookies}

        # Cloudflare
        if "cloudflare" in server_lower or "cf-ray" in headers or "cf-cache-status" in headers:
            technologies.add("Cloudflare")
        if any(c in cookie_names for c in ("__cf_bm", "__cfduid", "cf_clearance")):
            technologies.add("Cloudflare")

        # Nginx
        if "nginx" in server_lower:
            technologies.add("Nginx")

        # Apache
        if "apache" in server_lower:
            technologies.add("Apache")

        # Microsoft IIS / ASP.NET
        if "iis" in server_lower or "microsoft-iis" in server_lower:
            technologies.add("IIS")
        if "asp.net" in powered_lower or "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
            technologies.add("ASP.NET")
            technologies.add("IIS")

        # LiteSpeed
        if "litespeed" in server_lower:
            technologies.add("LiteSpeed")

        # Vercel
        if "vercel" in server_lower or "x-vercel-id" in headers or "x-vercel-cache" in headers:
            technologies.add("Vercel")

        # Netlify
        if "netlify" in server_lower or "x-nf-request-id" in headers:
            technologies.add("Netlify")

        # AWS / CloudFront
        if "cloudfront" in server_lower or "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
            technologies.add("AWS CloudFront")

        # Fastly
        if "fastly" in server_lower or "x-fastly-request-id" in headers:
            technologies.add("Fastly")

        # Language / Runtime headers
        if "php" in powered_lower or "phpsessid" in cookie_names:
            technologies.add("PHP")
        if "express" in powered_lower:
            technologies.add("Express")
        if "next.js" in powered_lower or "x-powered-by" in headers and "next.js" in headers["x-powered-by"].lower():
            technologies.add("Next.js")

        return list(technologies)

    def _normalize_domain(self, domain: str) -> str:
        """Strip protocol and path information to obtain base domain."""
        d = domain.strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0].strip()
        return d.rstrip(".")
