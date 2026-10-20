# Security and privacy model

SentinelAI is defensive and read-only. It does not execute uploaded content, agent generated code, or response actions. Event fields are normalized and common credential-bearing fields are removed or redacted. No user logs are included in Gemini prompts. The AI has no tool access and cannot assign severity.

Uploads are restricted to JSON/JSONL/CSV, bounded by byte and row limits, and parsed in memory. The app does not fetch URLs found in telemetry. VirusTotal is a fixed-host API integration for manual lookups only; private/reserved IPs are blocked, and users must explicitly confirm disclosure. Provider lookups may disclose an indicator; see the current provider terms and docs before use.

This implementation has no authentication or authorization. CORS and rate limiting do not replace access control. Do not expose it to the public internet or ingest data you are not authorized to analyze. Dataset deletion is provided; automated retention/deletion schedules are not implemented. Production should add authentication, per-tenant authorization, an egress firewall, durable queue, secrets manager, managed migrations, auditing, and retention controls.
