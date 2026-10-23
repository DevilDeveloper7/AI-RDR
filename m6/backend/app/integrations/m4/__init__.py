from ..base import BaseAdapter


class M4Adapter(BaseAdapter):
    """M4: threat-intelligence enrichment (reputation and context for hashes, IPs, domains).

    Provider-agnostic: M6 does not know or care which provider M4 uses. Enrichment is context
    only; it is never the detection decision.

    PROVISIONAL / M6 STUB.
    """

    module = "m4"

    def list_indicators(self):
        """Enriched indicators (see contracts.INDICATOR)."""
        raise NotImplementedError

    def enrich(self, indicator):
        """One enriched indicator, or None."""
        raise NotImplementedError
