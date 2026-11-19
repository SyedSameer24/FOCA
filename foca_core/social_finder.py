"""Public social profile detection from domain web pages."""

import logging
import re
from typing import Optional
from urllib.parse import urlparse
import requests

from foca_core.models import SocialProfileResult

logger = logging.getLogger(__name__)

GENERIC_SHARING_PATTERNS = [
    "share?url=",
    "share?text=",
    "intent/tweet",
    "intent/follow",
    "sharer.php",
    "sharer/sharer.php",
    "sharearticle",
    "share-offsite",
    "share_source",
    "plugins/share",
]

EXCLUDED_TWITTER = {
    "intent", "share", "home", "search", "explore", "hashtag",
    "privacy", "tos", "i", "login", "signup", "download", "about",
}

EXCLUDED_LINKEDIN = {
    "share", "sharing", "sharearticle", "intent", "feed", "login",
    "signup", "help", "legal", "pulse",
}

EXCLUDED_GITHUB = {
    "about", "pricing", "features", "join", "login", "signup",
    "topics", "explore", "pulls", "issues", "site", "security",
    "contact", "collections", "settings", "marketplace",
}

EXCLUDED_YOUTUBE = {
    "watch", "embed", "share", "playlist", "results", "feed",
    "live", "shorts", "upload", "about",
}

EXCLUDED_FACEBOOK = {
    "sharer", "dialog", "tr", "plugins", "privacy", "terms",
    "policies", "help", "pages", "group", "groups", "login",
}

EXCLUDED_INSTAGRAM = {
    "p", "reel", "tv", "explore", "stories", "developer",
    "about", "legal", "accounts",
}


class SocialFinder:
    """Discovers public social media presence linked from an organization's homepage."""

    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def __init__(self, user_agent: Optional[str] = None) -> None:
        """Initialize SocialFinder with optional user agent string."""
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT

    def find_profiles(self, domain: str, timeout: int = 10) -> SocialProfileResult:
        """Fetch homepage and extract social media profile links."""
        clean_domain = self._normalize_domain(domain)
        if not clean_domain:
            return SocialProfileResult(domain=domain, profiles={})

        html = self._fetch_homepage(clean_domain, timeout=timeout)
        if not html:
            return SocialProfileResult(domain=clean_domain, profiles={})

        profiles = self._extract_social_links(html)
        return SocialProfileResult(domain=clean_domain, profiles=profiles)

    def _fetch_homepage(self, domain: str, timeout: int) -> Optional[str]:
        """Fetch homepage HTML trying HTTPS first and HTTP as fallback."""
        headers = {"User-Agent": self.user_agent}

        for scheme in ("https://", "http://"):
            url = f"{scheme}{domain}"
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=True,
                )
                if response.status_code == 200:
                    return response.text
            except requests.exceptions.SSLError:
                if scheme.startswith("https"):
                    try:
                        response = requests.get(
                            url,
                            headers=headers,
                            timeout=timeout,
                            allow_redirects=True,
                            verify=False,
                        )
                        if response.status_code == 200:
                            return response.text
                    except Exception:
                        pass
            except requests.RequestException as req_err:
                logger.debug("Failed fetching %s: %s", url, str(req_err))
            except Exception as e:
                logger.debug("Unexpected error fetching %s: %s", url, str(e))

        return None

    def _extract_social_links(self, html: str) -> dict[str, str]:
        """Scan HTML text for target social media links and filter out generic sharing links."""
        profiles: dict[str, str] = {}
        found_urls = re.findall(r'https?://[^\s"\'<>]+', html)

        for raw_url in found_urls:
            url_lower = raw_url.lower()

            # Filter generic sharing dialogs and widgets
            if any(p in url_lower for p in GENERIC_SHARING_PATTERNS):
                continue

            try:
                parsed = urlparse(raw_url)
                netloc = parsed.netloc.lower()
                path = parsed.path.strip("/")
                segments = [s for s in path.split("/") if s]

                # Twitter / X
                if ("twitter.com" in netloc or "x.com" in netloc) and "twitter" not in profiles:
                    if len(segments) == 1 and segments[0].lower() not in EXCLUDED_TWITTER:
                        profiles["twitter"] = f"https://x.com/{segments[0]}"

                # LinkedIn
                elif "linkedin.com" in netloc and "linkedin" not in profiles:
                    if len(segments) >= 2 and segments[0].lower() in ("company", "in", "school"):
                        profiles["linkedin"] = f"https://www.linkedin.com/{segments[0]}/{segments[1]}"
                    elif len(segments) == 1 and segments[0].lower() not in EXCLUDED_LINKEDIN:
                        profiles["linkedin"] = f"https://www.linkedin.com/company/{segments[0]}"

                # GitHub
                elif "github.com" in netloc and "github" not in profiles:
                    if len(segments) >= 1 and segments[0].lower() not in EXCLUDED_GITHUB:
                        profiles["github"] = f"https://github.com/{segments[0]}"

                # YouTube
                elif "youtube.com" in netloc and "youtube" not in profiles:
                    if segments:
                        first = segments[0]
                        if first.startswith("@"):
                            profiles["youtube"] = f"https://www.youtube.com/{first}"
                        elif len(segments) >= 2 and first.lower() in ("c", "channel", "user"):
                            profiles["youtube"] = f"https://www.youtube.com/{first}/{segments[1]}"
                        elif first.lower() not in EXCLUDED_YOUTUBE:
                            profiles["youtube"] = f"https://www.youtube.com/@{first}"

                # Facebook
                elif "facebook.com" in netloc and "facebook" not in profiles:
                    if len(segments) >= 1 and segments[0].lower() not in EXCLUDED_FACEBOOK:
                        profiles["facebook"] = f"https://www.facebook.com/{segments[0]}"

                # Instagram
                elif "instagram.com" in netloc and "instagram" not in profiles:
                    if len(segments) >= 1 and segments[0].lower() not in EXCLUDED_INSTAGRAM:
                        profiles["instagram"] = f"https://www.instagram.com/{segments[0]}"

            except Exception as parse_err:
                logger.debug("Failed parsing candidate social url %s: %s", raw_url, str(parse_err))

        return profiles

    def _normalize_domain(self, domain: str) -> str:
        """Strip protocol and path information to obtain base domain."""
        d = domain.strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/", 1)[0].split(":", 1)[0].strip()
        return d.rstrip(".")
