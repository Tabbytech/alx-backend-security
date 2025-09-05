from django.test import TestCase, Client
from django.core.cache import cache
from ip_tracking.models import RequestLog, BlockedIP


class IPTrackingMiddlewareTest(TestCase):
    def setUp(self):
        self.client = Client()
        cache.clear()

    def test_logging(self):
        """Middleware should log requests into RequestLog."""
        response = self.client.get("/test/")
        self.assertEqual(response.status_code, 200)

        log = RequestLog.objects.last()
        self.assertIsNotNone(log)
        self.assertEqual(log.ip_address, "127.0.0.1")
        # country/city may be None if ipinfo fails
        self.assertTrue(hasattr(log, "country"))
        self.assertTrue(hasattr(log, "city"))

    def test_blacklist(self):
        """Requests from blocked IPs should return 403."""
        BlockedIP.objects.create(ip_address="127.0.0.1")
        response = self.client.get("/test/")
        self.assertEqual(response.status_code, 403)

    def test_cache(self):
        """Geo data should be cached after first request."""
        self.client.get("/test/")
        ip = RequestLog.objects.last().ip_address
        cached_geo = cache.get(ip)
        self.assertIsNotNone(cached_geo)
        self.assertIn("country", cached_geo)
        self.assertIn("city", cached_geo)

class RateLimitTest(TestCase):
    def setUp(self):
        self.client = Client()

    def test_rate_limit(self):
        url = "/login/"
        for i in range(5):  # 5 allowed requests
            response = self.client.post(url)
            self.assertEqual(response.status_code, 200)

        # 6th request should fail
        response = self.client.post(url)
        self.assertEqual(response.status_code, 429)
