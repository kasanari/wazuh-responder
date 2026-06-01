# syntax=docker/dockerfile:1.4
FROM ghcr.io/astral-sh/uv:alpine

# Copy the project into the image
COPY . /app

# Disable development dependencies
ENV UV_NO_DEV=1

# Sync the project into a new environment, asserting the lockfile is up to date
WORKDIR /app
RUN uv sync --locked

CMD ["uv", "run", "app.py"]