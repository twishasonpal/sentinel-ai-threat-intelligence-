# Deployment guidance

The included Compose setup is a local demonstration. Before any shared or production deployment, add authenticated access control and tenant authorization, TLS, managed PostgreSQL with migrations and backups, a durable job queue, a secrets manager, egress filtering, log redaction, retention policy, monitoring, and rate-limit storage. Do not publish PostgreSQL or Redis. Keep threat-intelligence lookups opt-in and governed by provider terms.
