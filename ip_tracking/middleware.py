import logging
import json
import ipinfo
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils.timezone import now
from django.conf import settings
from ipware import get_client_ip
from .models import RequestLog, BlockedIP

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize ipinfo handler (ensure IPINFO_TOKEN is set in settings)
ipinfo_handler = ipinfo.getHandler(getattr(settings, "IPINFO_TOKEN", None))


class IPTrackingMiddleware:
    """
    Middleware that:
    - Blocks requests from blacklisted IPs.
    - Tracks per-IP request count and accessed paths in Redis (1 hour).
    - Fetches and caches GeoIP info via ipinfo (24 hours).
    - Logs requests to DB and console/file.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Extract client IP
        ip, is_routable = get_client_ip(request)
        ip_address = ip if ip else "0.0.0.0"

        # 1. Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            logger.warning(f"Blocked request from blacklisted IP: {ip_address}")
            return HttpResponseForbidden("Forbidden: Your IP has been blocked.")

        # 2. Track request count & unique paths (per IP, 1h expiry)
        cache_key = f"ip:{ip_address}"
        ip_data = cache.get(cache_key)
        if ip_data is None:
            ip_data = {"count": 0, "paths": []}

        ip_data["count"] += 1
        if request.path not in ip_data["paths"]:
            ip_data["paths"].append(request.path)

        cache.set(cache_key, ip_data, timeout=3600)  # 1h

        # 3. Get Geo data (cached 24h)
        geo_data = cache.get(f"geo:{ip_address}")
        if not geo_data:
            try:
                details = ipinfo_handler.getDetails(ip_address)
                geo_data = {
                    "country": getattr(details, "country", None),
                    "city": getattr(details, "city", None),
                }
                cache.set(f"geo:{ip_address}", geo_data, 60 * 60 * 24)
            except Exception as e:
                logger.error(f"Geo lookup failed for {ip_address}: {e}")
                geo_data = {"country": None, "city": None}

        # 4. Log request to DB
        try:
            RequestLog.objects.create(
                ip_address=ip_address,
                timestamp=now(),
                path=request.path,
                country=geo_data["country"],
                city=geo_data["city"],
            )
        except Exception as e:
            logger.error(f"Failed to save RequestLog for {ip_address}: {e}")

        # 5. Log to console/file
        logger.info(
            f"[{ip_address}] ({geo_data['country']}, {geo_data['city']}) "
            f"-> {request.path} | Count: {ip_data['count']}"
        )

        # Continue request cycle
        return self.get_response(request)
