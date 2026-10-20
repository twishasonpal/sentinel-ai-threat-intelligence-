# Reproducible evaluation

Run `python evals/run_evaluations.py` from this project root. The script parses the included synthetic authentication JSONL, runs actual deterministic detection and correlation code, validates report event references, calculates rule precision/recall/F1 using the expected rule labels, and writes `results.json` and `REPORT.md`. The fixture is small and synthetic; its metrics are not representative of enterprise detection performance.
