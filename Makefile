.PHONY: backend frontend test eval
backend:
	cd backend && python run.py
frontend:
	cd frontend && npm run dev
test:
	cd backend && python -m pytest
eval:
	python evals/run_evaluations.py
