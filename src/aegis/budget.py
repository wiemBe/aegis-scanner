import time

from aegis.models import BudgetUsage, ProviderRunMetadata
from aegis.settings import Settings


class BudgetExceeded(ValueError):
    pass


class ScanBudget:
    def __init__(
        self,
        settings: Settings,
        usage: BudgetUsage,
        *,
        max_requests: int | None = None,
        time_budget_seconds: float | None = None,
    ) -> None:
        self.settings = settings
        self.usage = usage
        self.max_requests = min(
            max_requests or settings.max_requests_per_scan, settings.max_requests_per_scan
        )
        self.time_budget_seconds = min(
            time_budget_seconds or settings.scan_timeout_seconds,
            settings.scan_timeout_seconds,
        )
        self.deadline = time.monotonic() + self.time_budget_seconds
        # Per-scan sink for the most recent provider run facts (set by the gateway planner).
        # Local to one run(), so concurrent scans never share provider metadata.
        self.provider_metadata: ProviderRunMetadata | None = None

    def check_time(self) -> None:
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded("TIME_BUDGET")

    def remaining_time_ms(self) -> int:
        return max(0, round((self.deadline - time.monotonic()) * 1000))

    def request(self) -> None:
        self.check_time()
        if self.usage.requests >= self.max_requests:
            raise BudgetExceeded("REQUEST_BUDGET")
        self.usage.requests += 1

    def iteration(self) -> None:
        self.check_time()
        if self.usage.iterations >= self.settings.max_iterations:
            raise BudgetExceeded("ITERATION_BUDGET")
        self.usage.iterations += 1

    def model_call(self, reservation: int) -> None:
        self.check_time()
        if self.usage.model_calls >= self.settings.max_model_calls:
            raise BudgetExceeded("MODEL_CALL_BUDGET")
        if self.usage.reserved_tokens + reservation > self.settings.max_tokens_per_scan:
            raise BudgetExceeded("TOKEN_RESERVATION_BUDGET")
        self.usage.model_calls += 1
        self.usage.reserved_tokens += reservation
