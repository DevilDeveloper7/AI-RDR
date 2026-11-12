# Section 9: threat-intelligence provider decision (replacement text)

*Suggested wording for Section 9 of the Implementation Document. Update §15,
§17.7 and §17.8 to match.*

---

The original design used IBM X-Force Exchange as the threat-intelligence
source. During implementation planning we found that X-Force no longer offers
free API access suitable for an academic prototype, so it was dropped. We
also considered MISP. Because MISP is a self-hosted sharing platform rather
than a reputation feed, it would need its own deployment and feed curation
without adding lookup coverage for the prototype, so it is recorded as future
work. The prototype therefore uses the abuse.ch services (MalwareBazaar for
file hashes, ThreatFox for indicators of compromise, and URLhaus for
malware-distribution hosts) as the primary source. All three are accessed
with a single free Auth-Key. AlienVault/LevelBlue Open Threat Exchange (OTX)
is a secondary, context-only source. Because OTX is community-contributed and
comparatively noisy, an OTX match alone can raise an indicator to
"suspicious" but never to "malicious". Both sources sit behind a common
provider interface, so the source can be changed without affecting the rest
of the pipeline. Consistent with Section 2, enrichment runs asynchronously and
provides context only: it is not a detection decision signal. An indicator
that is not found, or whose lookup fails, is reported as "unknown", never as
"clean". The free-tier terms and rate limits of both services must be
re-verified before final submission, because providers can change them.
