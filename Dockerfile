FROM python:3.11-slim-bookworm

# The installer requires curl (and certificates) to download the release archive
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates openssl

# Download the latest installer
ADD https://astral.sh/uv/install.sh /uv-installer.sh

# Run the installer then remove it
RUN sh /uv-installer.sh && rm /uv-installer.sh

# Ensure the installed binary is on the `PATH`
ENV PATH="/root/.local/bin/:$PATH"

# Copy the project into the image
ADD pyproject.toml /app/
ADD smtp_tlsa_verify /app/
ADD . /app

# Sync the project into a new environment
WORKDIR /app
RUN uv sync --no-dev --group fastapi
EXPOSE 8000
CMD [ "/app/.venv/bin/python", "-m", "uvicorn", "--host", "0.0.0.0", "--port", "8000", "smtp_tlsa_verify.api:app"]