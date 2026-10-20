# Architecture

Flask validates uploads and stores normalized events. A bounded worker invokes a typed LangGraph state graph after deterministic rules run. Seven distinct agent modules summarize, extract indicators, analyze frequency anomalies, correlate incidents, investigate, report, and validate report references. SQLAlchemy stores datasets, events, findings, indicators, incidents, reports, jobs, agent traces, and reviews. React reads all normal dashboard data from the REST API.

The worker persists job status but is an in-process thread pool. Restarted queued/running work is marked interrupted; mid-run resume and multi-process coordination are not supported.
