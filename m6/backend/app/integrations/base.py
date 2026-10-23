"""Shared pieces for the M1-M5 adapter boundary.

PROVISIONAL / M6 STUB: the method names and payloads of every adapter are M6's
proposal. They are NOT confirmed interfaces of M1-M5 (see docs/integration/adapters.md).
An adapter only talks to its module and returns plain dicts that match
integrations/contracts.py. Adapters know nothing about Flask or React.
"""


class IntegrationError(Exception):
    """Base class for controlled adapter failures. Flask maps these to JSON errors."""

    code, status = "INTEGRATION_ERROR", 502

    def __init__(self, message="Integration error"):
        super().__init__(message)
        self.message = message


class IntegrationUnavailable(IntegrationError):
    code, status = "INTEGRATION_UNAVAILABLE", 503


class IntegrationTimeout(IntegrationError):
    code, status = "INTEGRATION_TIMEOUT", 504


class MalformedResponse(IntegrationError):
    code, status = "MALFORMED_RESPONSE", 502


class ActionRejected(IntegrationError):
    code, status = "ACTION_REJECTED", 409


class BaseAdapter:
    module = ""  # "m1" ... "m5"
    kind = "real"  # mock adapters set this to "mock"

    def health(self):
        """Return {"status": "Connected"|"Stubbed"|"Warning"|"Failed", "detail": str}."""
        raise NotImplementedError
