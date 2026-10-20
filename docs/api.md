# API reference

All routes are under `/api/v1`. Upload a supported file using `multipart/form-data` field `file`. JSON must be an array or contain an `events` array; JSONL has one event object per line; CSV uses its first row as field names.

- `GET /health`: database and optional-provider status.
- `GET /overview`: actual persisted counts and recent jobs.
- `POST /datasets`: parse and persist authorized events; returns validation warnings.
- `POST /datasets/sample`: load the labelled synthetic JSONL.
- `GET /datasets?page=1&limit=25`; `GET /datasets/{id}`; `GET /datasets/{id}/events?page=1&limit=50`.
- `DELETE /datasets/{id}`: deletes the dataset and its associated findings, jobs, incidents, reports, and reviews.
- `POST /datasets/{id}/analyze`: returns a queued job; poll `GET /jobs/{job_id}` and read `GET /jobs/{job_id}/trace`.
- `GET /datasets/{id}/findings?severity=high`; `GET /incidents?severity=high&status=open&dataset_id=...`.
- `GET /incidents/{id}` includes the evidence timeline, findings, report, trace, and review history.
- `GET /incidents/{id}/report`; `POST /incidents/{id}/review` accepts `accepted`, `rejected`, `further_investigation`, or `reviewed` plus an optional note.
- `POST /intelligence/lookup` requires `{dataset_id, kind, value, authorized: true}`. `kind` is `ip`, `domain`, `hash`, or `url`. Private/reserved IPs are rejected.
- `GET /intelligence/results/{result_id}` returns normalized provider data.

Errors return a JSON `error` string. The app has no authentication, so bind it only to trusted local infrastructure.
