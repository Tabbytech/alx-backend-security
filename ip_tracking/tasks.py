from celery import shared_task
from django.core.cache import cache
from django.utils import timezone
from .models import SuspiciousIP

SENSITIVE_PATHS = ["/admin", "/login"]

@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IPs from Redis logs
    and store them in SuspiciousIP.
    """
    keys = cache.keys("ip:*")  # e.g. ip:127.0.0.1
    flagged = 0

    for key in keys:
        ip_data = cache.get(key)
        if not ip_data:
            continue

        ip_address = key.split(":")[1]
        count = ip_data.get("count", 0)
        paths = ip_data.get("paths", [])

        reasons = []

        # Rule 1: High request rate
        if count > 100:
            reasons.append(f"Excessive requests: {count} in last hour")

        # Rule 2: Sensitive paths
        for path in paths:
            if any(path.startswith(sp) for sp in SENSITIVE_PATHS):
                reasons.append(f"Accessed sensitive path: {path}")

        # Save suspicious IPs
        for reason in reasons:
            SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                reason=reason,
                defaults={"flagged_at": timezone.now()},
            )
            flagged += 1

    return f"Checked {len(keys)} IPs, flagged {flagged} suspicious at {timezone.now()}"
