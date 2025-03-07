# Specify the base image
FROM python:3.12-slim

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1
ENV PIP_ROOT_USER_ACTION=ignore
ENV PYTHONDONTWRITEBYTECODE=1

# Install system dependencies and create non-root user
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid 1000 -ms /bin/bash appuser \
    && mkdir -p /home/appuser/.local/bin /home/appuser/.local/lib

# Make port 8501 available
EXPOSE 8501

# Set the working directory
WORKDIR /home/appuser

# Set virtual environment path
ENV VIRTUAL_ENV=/home/appuser/venv
ENV PATH="$PATH:/home/appuser/.local/bin:/home/appuser/.local/lib:${VIRTUAL_ENV}/bin"

# Copy requirements first to leverage Docker cache
COPY --chown=appuser:appuser requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv ${VIRTUAL_ENV} \
    && ${VIRTUAL_ENV}/bin/pip install --no-cache-dir --upgrade pip \
    && ${VIRTUAL_ENV}/bin/pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health

# Configure the entrypoint
ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]