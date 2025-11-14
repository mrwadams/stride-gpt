# Specify the base image with SHA256 for reproducibility and security
FROM python:3.12-slim@sha256:d86b4c74b936c438cd4cc3a9f7256b9a7c27ad68c7caf8c205e18d9845af0164

# Turns off buffering for easier container logging and updating pip as root
ENV PYTHONUNBUFFERED=1
ENV PIP_ROOT_USER_ACTION=ignore

# Create the non-root user and set up environment
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid 1000 -ms /bin/bash appuser && \
    pip install --no-cache-dir --upgrade pip && \
    mkdir -p /home/appuser/.local/bin /home/appuser/.local/lib

# Make port 8501 available to the world outside this container
EXPOSE 8501

# Set the working directory in the container
WORKDIR /home/appuser

# Copy the current directory contents into the container
COPY --chown=appuser:appuser . /home/appuser

USER appuser

# Add new local folders to environment $PATH
ENV PATH="$PATH:/home/appuser/.local/bin:/home/appuser/.local/lib:/home/appuser/venv/bin"
ENV VIRTUAL_ENV=/home/appuser/venv

# Install pip requirements and validate
RUN python -m venv ${VIRTUAL_ENV}
RUN ${VIRTUAL_ENV}/bin/pip install --no-cache-dir -r requirements.txt && \
    ${VIRTUAL_ENV}/bin/pip check

# Test if the container is listening on port 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health

# Configure the container to run as an executable with security enhancements
ENTRYPOINT ["streamlit", "run", "main.py", \
            "--server.port=8501", \
            "--server.address=0.0.0.0", \
            "--server.enableXsrfProtection=true"]
