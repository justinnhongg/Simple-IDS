FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

# Install runtime packages and create non-root user
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system app \
    && useradd --system --gid app app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .
RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /app/logs /app/data \
    && chown -R app:app /app

USER app

EXPOSE 8000
ENTRYPOINT ["/app/entrypoint.sh"]
