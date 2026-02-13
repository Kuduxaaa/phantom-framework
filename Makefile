.PHONY: install run test clean

install:
	cd backend && pip install -r requirements.txt

run:
	cd backend && uvicorn app.main:app --reload

test:
	cd backend && pytest

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
