# Specify the base image
FROM python:3.12-slim

# Turns off buffering for easier container logging and updating pip as root
ENV PYTHONUNBUFFERED=1
ENV PIP_ROOT_USER_ACTION=ignore

# Create the non-root user to run the app as
RUN groupadd --gid 1000 appuser && useradd --uid 1000 --gid 1000 -ms /bin/bash appuser

# Upgrade pip
RUN pip install --no-cache-dir --upgrade pip virtualenv

# Make port 8501 available to the world outside this container
EXPOSE 8501

# Set the working directory in the container
WORKDIR /home/appuser

# Copy the current directory contents into the container at /app
COPY . /home/appuser

# Give the new user permissions to the copied files
RUN chown -R appuser /home/appuser

USER appuser
WORKDIR /home/appuser

# Create the local folders for the pip libraries
RUN mkdir -p /home/appuser/.local/bin /home/appuser/.local/lib

# Add new local folders to environment $PATH
ENV PATH="$PATH:/home/appuser/.local/bin:/home/appuser/.local/lib:/home/appuser/venv/bin"
ENV VIRTUAL_ENV=/home/appuser/venv

# Install pip requirements
RUN virtualenv ${VIRTUAL_ENV}
RUN . ${VIRTUAL_ENV}/bin/activate && pip install --no-cache-dir -r requirements.txt

# Test if the container is listening on port 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health

# Configure the container to run as an executable
ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
