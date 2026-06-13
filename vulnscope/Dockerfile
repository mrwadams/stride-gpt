# VulnScope — single image serving the Streamlit UI; the CLI runs in the same
# image via `docker run --entrypoint python ... cli.py ...`.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . /app

# Non-root runtime.
RUN useradd --create-home --uid 1000 appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8501/_stcore/health', timeout=4).status == 200 else 1)" || exit 1

# Default: launch the Streamlit UI. Override the entrypoint to use the CLI:
#   docker run --rm -v $PWD:/data --entrypoint python vulnscope \
#     cli.py --threat-model /data/tm.json --findings /data/results.sarif -o /data/report
ENTRYPOINT ["streamlit", "run", "app.py", \
            "--server.port=8501", "--server.address=0.0.0.0"]
