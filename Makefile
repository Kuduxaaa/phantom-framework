.PHONY: install install\:backend install\:frontend \
       run run\:backend run\:frontend \
       proxy test clean

# ── Install ───────────────────────────────────────────────

install: install\:backend install\:frontend

install\:backend:
	cd backend && python3 -m pip install -r requirements.txt

install\:frontend:
	cd frontend && npm install

# ── Run ───────────────────────────────────────────────────

run: run\:backend run\:frontend

run\:backend:
	cd backend && python3 -m uvicorn app.main:app --reload &

run\:frontend:
	cd frontend && npm run dev

# ── Proxy ─────────────────────────────────────────────────

proxy:
	cd backend && python3 -c "from app.core.proxy.server import run; run()"

# ── Utils ─────────────────────────────────────────────────

test:
	cd backend && python3 -m pytest

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
