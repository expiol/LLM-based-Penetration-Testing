FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
  && apt-get install -y --no-install-recommends nmap sqlmap curl \
  && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY configs /app/configs
COPY data /app/data
COPY docs /app/docs
COPY tests /app/tests

RUN pip install --no-cache-dir -e .[dev]

ENTRYPOINT ["autopentest"]
