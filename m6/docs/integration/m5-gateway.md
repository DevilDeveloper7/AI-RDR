# M5 gateway link (M6 -> M5Client -> restricted SSH -> M5 gateway)

M5 has **no REST server**. M6 talks to M5 only through M5's own `M5Client`, which signs each request and sends it over SSH to a
fixed, restricted command on the endpoint (`ai_rdr_m6.py`, the M5 gateway). M5 stays authoritative for risk decisions,
authorization and response execution. M6 only submits an analyst's request and shows what M5 reports.

## What exists in M6 now

| Piece | File | Purpose |
|---|---|---|
| M5's client, unchanged | `backend/app/integrations/m5/vendor/ai_rdr_m6.py` | `M5Client`, `SSHTransport`, the gateway. A byte-for-byte copy (sha256 `9597b5cd5b3b93a9aef23e6e7d25ff7ba3b0f8e3c03abff702637a8a296931eb`). Replace it only with a newer file from the M5 developer. |
| Settings | `.../m5/gateway_config.py` | Environment variables; key-file checks |
| Link | `.../m5/gateway.py` | `M5Gateway`: reads, health, `submit_action`, `retry_action`, `action_status`, `outbox`, `acknowledge` |
| Durable state | `.../m5/state_store.py` | SQLite file in `M6_DATA_DIR`: received M5 events and action requests |
| Event delivery | `.../m5/delivery.py` | `outbox()` -> store -> `acknowledge()` |
| Check tool | `backend/m5_tool.py` | Read-only command-line check plus event polling. It cannot send an action. |

**Read-only link (switch on with `M5_LINK_ENABLED=true`):**
- `GET /api/v1/m5/health`, `/m5/cases`, `/m5/cases/<case_id>`, `/m5/cases/<case_id>/timeline`, `/m5/cases/<case_id>/risk-decisions`
  return M5's own data unchanged plus `meta: {source: "m5-gateway", is_mock: false, read_only: true}`. Optional `limit`, `offset`, `after`.
  When the link is off, not configured or M5 is unreachable they answer with a clear error (503), never with placeholder data.
- The **M5 row on Integration Status** shows `SSH gateway (read-only): Connected/Warning/Failed`. It stays `Stubbed` while the link works,
  because the alert screens still use the M5 mock, and turns to `Warning` if the gateway is configured but failing. The result is cached for 30 seconds;
  the row's **Check** button asks M5 again.
- Like every other M6 route these have no login. They are off by default and only answer when the M5 link is switched on.

**Not wired yet** (waiting for decisions, see the end): the alert screens, the Action/Override screen and `M5_MODE=real` still use the M5 mock.
No browser-facing route can send an action to M5.

## How an analyst action is sent (`M5Gateway.submit_action`)
1. Validate locally: action must be one of M5's exact names (`freeze verify kill isolate thaw undo approve_containment`), the analyst's
   role must allow it, the reason must be meaningful (>= 10 characters, >= 2 words), and parameters must follow M5's rules:
   `freeze` needs a complete `target` (`pid`, `start_ticks`, `boot_id`); `undo` needs `resource_key`; the others use an optional
   `operation_id`. `approve_containment` and `isolate` are different actions.
2. Read the latest case from M5 and take `expected_sequence` from `case.last_sequence`. Never reused from earlier.
3. Make a new idempotency key (`m6-<uuid>`), compute the request id (`M5Client.action_id`), and **save the intent first**.
4. Send `request_action` as the analyst's identity (type `user`). The identity and roles come from M6's server settings only.
5. M5 answers with the action record. M6 reports `completed`, `failed` or `uncertain` exactly as M5 says (`completion_verified` is M5's flag).
6. If the SSH result is uncertain (timeout, dropped session, expired, unreadable answer), M6 **never re-sends blindly**. It asks
   M5 `get_action(request_id)`: a record means that is the answer; no record means status `not_received` and `retry_allowed`;
   if M5 cannot be asked the status is `unknown`.
7. `retry_action(key)` re-checks first and only then re-sends the identical request with the same key and the same
   `expected_sequence` (M5 treats it idempotently). If the case has moved on, M5 refuses it and the analyst starts a new action.

## Event delivery (`EventDelivery.poll_once`, or `python3 backend/m5_tool.py poll`)
Uses the **service** principal (role `connector`; M5 refuses `outbox`/`acknowledge` for an analyst identity). Events are fetched,
saved in one database transaction, and only then acknowledged (at most 100 per call). A storage failure acknowledges nothing; a
lost acknowledgement just means the same events arrive again and are recognised as duplicates; an event id that comes back with
different content is never overwritten or acknowledged.

## Settings (`.env`, see `.env.example`)
Required: `M5_SSH_HOST`, `M5_SSH_USER`, `M5_SSH_IDENTITY_FILE`, `M5_SSH_KNOWN_HOSTS_FILE`, `M5_GATEWAY_KEY_FILE`, `M5_AGENT_ID`.
Optional: `M5_SSH_PORT` (22), `M5_ISSUER` (`m6-backend`), `M5_TIMEOUT` (45, range 5-60), `M5_SERVICE_ID` (`m6-backend`),
`M5_ANALYST_ID` (defaults to `ANALYST_NAME`), `M5_ANALYST_ROLES` (`analyst`; `viewer`/`analyst`/`responder`), `M6_DATA_DIR` (`./data`).
Keys are files, never values. Host-key checking stays strict (`StrictHostKeyChecking=yes`, `BatchMode=yes`, fixed remote command).

## Deployment prerequisites (M5 developer / endpoint)
- `m6_gateway.enabled: true` in the endpoint's `/etc/ai-rdr/config.json`, with `issuer` equal to `M5_ISSUER`.
- A root-owned `0600` gateway key file on the endpoint (`m6_gateway.key_file`); the **same** bytes in `M5_GATEWAY_KEY_FILE`.
- An SSH account for M6 whose authorized key is restricted to the gateway command, plus the `sudo -n` rule that command needs.
- The endpoint's host key already in `M5_SSH_KNOWN_HOSTS_FILE`. Clocks within 30 seconds (requests live at most 60 seconds).
- Confirm `m6_gateway.role_permissions`: M6 checks M5's default policy first (viewer: read; analyst: freeze, verify, thaw, undo;
  responder: all seven); M5 still decides.

## Check it (no action is ever sent)
```bash
python3 backend/m5_tool.py health
python3 backend/m5_tool.py cases
python3 backend/m5_tool.py case CASE_ID
python3 backend/m5_tool.py poll
```

## M5 response shapes (for the screens, once wired)
`get_case`: `case` (case_id, title, severity low/medium/high/critical, lifecycle open/investigating/resolved/closed,
disposition, last_sequence, ...), `latest_risk_decision` (M5's decision object or null), `process_operations`,
`resource_operations`, `operation_count`, `operations_truncated`. Process operation status values include PREPARING, PENDING,
FROZEN, REVIEW, THAWING, THAWED, CONTAINING, KILLED, FAILED, STALE_BOT-style terminal states. `timeline`/`risk_decisions`:
`items` (events with `case_sequence`) and `next_after`.

## Open decisions before the screens can use M5 (see the report)
1. **Authentication in M6.** M6 has no login ("no login in M6 scope"). Analyst identity is one configured name. Sending real
   containment actions needs a decision on how M6 authenticates its analysts.
2. **Alert-to-case link.** M5 cases are keyed by M5's own case id (from Wazuh alerts / process identity). M6 alerts are keyed by
   M2 `detection_id` / M3 derived ids. M5's gateway exposes no mapping between them.
3. **Response vocabulary.** M6's screens show Frozen/Isolated/Thawed; M5 reports operation states and risk levels of its own.
