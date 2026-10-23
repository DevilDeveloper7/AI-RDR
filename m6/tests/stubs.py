"""Test doubles for adapter failures."""


class Failing:
    """Stand-in adapter whose every call fails (simulates an unavailable module)."""

    def __init__(self, exc):
        self.exc = exc
        self.kind = "test-stub"

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise self.exc
        return call
