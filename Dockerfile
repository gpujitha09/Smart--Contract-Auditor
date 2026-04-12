FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
		&& apt-get install -y --no-install-recommends curl \
		&& rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 appuser \
		&& chown -R appuser:appuser /app

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
	CMD curl -f http://localhost:7860/health || exit 1

USER appuser

CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
