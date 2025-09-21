FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Install curl for health checks in wait-for.sh
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl \
	&& rm -rf /var/lib/apt/lists/* \
	&& groupadd --system app \
	&& useradd --system --gid app app

COPY . .
RUN chmod +x /app/wait-for.sh /app/run_attack.sh \
    && chown -R app:app /app

USER app

EXPOSE 9000

ENTRYPOINT ["/app/run_attack.sh"]
CMD ["--all"]
