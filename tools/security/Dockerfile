FROM docker.io/library/composer:2 AS composer
FROM docker.io/library/php:8.5-cli-bookworm
# The official CLI image already enables every extension the scanners need.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip \
    && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /app
