# M1-M5 integration documents

**Status: PROVISIONAL / M6 STUB.** No teammate has confirmed a real interface for M1, M2, M3, M4 or M5. Every method, endpoint or schema in these documents is a proposal made by M6, not an existing API. Until the module owners confirm them, the modules run as built-in mock adapters (`M1_MODE=mock` to `M5_MODE=mock`) and nothing is connected to a real module.

| Document | Purpose |
|---|---|
| [`adapters.md`](adapters.md) | The adapter boundaries: who owns what, data contracts with examples, adapter methods, error handling, how a mock is replaced |
| [`handoff.md`](handoff.md) | What a teammate must provide to connect M1-M5, with sample payloads and open questions |

Related: [`../architecture.md`](../architecture.md) (overall design and current status) and [`../api/README.md`](../api/README.md) (the M6 REST API).
