FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY configs /app/configs
COPY data /app/data

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["autopentest"]
