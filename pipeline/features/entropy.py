"""Shannon entropy over *real* captured byte content — and the decoder needed to get
real bytes back out of the two sources that actually have any.

Per planning/feature-engineering-progress.md's explicit warning: none of the four Tier 1
sources obviously carry literal file byte content, so this module exists to make the
"is there real signal here" answer auditable rather than assumed. What was actually found
by inspecting `raw_fields` on a running interpreter before writing any of this (see each
dataset's pipeline/features/<name>.py docstring for the full per-source finding):

- ELFEN's `fileops` `write` syscall args include a `buffer: b'...'` fragment — literally
  Python's `repr()` of the bytes ELFEN's sandbox captured for that write call (truncated
  by the sandbox itself well below the syscall's declared `size`, e.g. a 512000-byte
  write only has ~40-250 bytes of `buffer` text) — genuine, if small and truncated,
  sampled byte content. 268 of 314 `write` events across the whole 34,687-row dataset
  decode cleanly back to bytes via `decode_bytes_repr` below (the other 46 contain a
  backslash/quote edge case `ast.literal_eval` can't round-trip losslessly — logged, not
  silently coerced).
- EN2025's CAPE report has a `Buffer` argument on `NtWriteFile` calls in the same
  repr-with-visible-escapes shape (e.g. `"\\xff\\xfe"`) — also genuine sampled byte
  content (CAPE truncates its own capture per call, independent of the real write
  `Length`). Spot-checked at ~99.6% clean decode rate on a 20K-row sample.
- The Ransomware Lifecycle dataset's ftrace/net/perf traces do NOT carry this anywhere —
  verified by listing every distinct ftrace `event` name (all syscall enter/exit names,
  `details` is only pointer addresses / return codes / byte *counts*, never the bytes
  written) and by checking `sys_enter_newfstatat`'s `details` (return codes only, no
  `st_size`). No file-size-before/after signal exists either. `entropy_score` is a
  documented null for this source (see pipeline/features/lifecycle.py) — the
  `crypto_algo`/`key_bits` fields ARE real and are used as a separate, explicitly
  non-equivalent `crypto_op_rate` proxy column instead of a fabricated entropy number.
- Linux-APT-2024's syscheck FIM rows carry `size_before`/`size_after` and MD5/SHA1/SHA256
  hashes but never byte content (hashes are one-way; a size delta alone says nothing
  about byte distribution). `entropy_score` is a documented null for this source too, and
  no extension-based ransomware proxy is applied — this dataset isn't ransomware data, so
  a "renamed to known ransomware extension" flag would be a category error, not a proxy.
"""

from __future__ import annotations

import ast
import math
import warnings
from collections import Counter


def shannon_entropy(data: bytes) -> float | None:
    """Shannon entropy in bits/byte of `data`. None (not 0.0) for empty input — an empty
    capture is a missing sample, not a measured zero-entropy buffer."""
    if not data:
        return None
    n = len(data)
    counts = Counter(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def decode_bytes_repr(body: str) -> bytes | None:
    """Reconstruct real bytes from the literal body of a Python bytes repr (the text
    between the b'...' quotes, already JSON-unescaped by json.loads). Both ELFEN's
    sandbox and CAPE (EN2025) emit their captured buffers this way. Uses
    `ast.literal_eval` (not `codecs.escape_decode`/`unicode_escape`) because that's the
    exact grammar `repr(bytes)` produces, including how it escapes an embedded quote or
    backslash — the safest available round-trip for this specific format. Returns None
    (and the caller counts it, never silently drops it) when the body contains something
    `ast.literal_eval` can't parse as a bytes literal (observed on 46/314 = 14.6% of
    ELFEN writes and 28,527/775,395 = 3.7% of EN2025 writes on the full-dataset run —
    usually a stray unescaped quote/backslash in the sandbox's own capture, not something
    this decoder can recover). CPython emits a SyntaxWarning per attempt for a body with
    an unrecognized backslash escape (e.g. `\\K`, `\\?`) even though it still parses the
    literal (unrecognized escapes are kept as literal backslash+char, matching what
    `repr()` itself would have produced only for the backslash character) — deliberately
    silenced here since it fires on a meaningful fraction of otherwise-successful calls
    and would otherwise flood output on a full dataset run."""
    if not body:
        return None
    for quote in ("'''", '"""'):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                value = ast.literal_eval(f"b{quote}{body}{quote}")
            if isinstance(value, bytes):
                return value
        except (SyntaxError, ValueError):
            continue
    return None


def entropy_from_repr(body: str | None) -> float | None:
    """decode_bytes_repr + shannon_entropy in one step; None on any failure."""
    if not body:
        return None
    decoded = decode_bytes_repr(body)
    if decoded is None:
        return None
    return shannon_entropy(decoded)


# SDD Table 5.1a: encryption_rate is defined as "proportion of files with entropy > 7.2
# in the window" -- kept as a module constant so every dataset module applies the exact
# same threshold rather than each hardcoding its own copy of 7.2.
HIGH_ENTROPY_THRESHOLD = 7.2
