"""Deterministic policy layer. Every planned test must pass this before execution."""
from urllib.parse import urlparse

class ScopeViolation(Exception):
    pass

# test_id -> HTTP methods that test may use. Anything else is denied.
DEFAULT_TESTS = {"cross_agency_access": {"GET"}, "security_headers": {"GET"}, "rate_limit": {"GET"},
                 "price_integrity": {"POST"}, "zap_passive": {"GET"}}

class ScopeGuard:
    def __init__(self, allowed_hosts=("127.0.0.1", "localhost"), allowed_tests=None, max_requests=150):
        self.hosts = set(allowed_hosts)
        self.tests = {k: set(v) for k, v in (allowed_tests or DEFAULT_TESTS).items()}
        self.max_requests, self.used = max_requests, 0

    def check_host(self, base_url: str):
        host = urlparse(base_url).hostname
        if host not in self.hosts:
            raise ScopeViolation(f"host {host} not in scope")

    def authorize(self, base_url: str, method: str, test_id: str, cost: int = 2):
        self.check_host(base_url)
        if test_id not in self.tests:
            raise ScopeViolation(f"test {test_id} not in approved catalogue")
        if method.upper() not in self.tests[test_id]:
            raise ScopeViolation(f"method {method} not allowed for {test_id}")
        if self.used + cost > self.max_requests:
            raise ScopeViolation("request budget exhausted")
        self.used += cost
