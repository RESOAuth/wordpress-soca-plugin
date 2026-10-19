FROM docker.io/library/composer:2 AS composer
FROM docker.io/library/php:8.5-cli-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends git unzip libonig-dev libxml2-dev libcurl4-openssl-dev && docker-php-ext-install -j2 mbstring dom simplexml xml xmlwriter curl && rm -rf /var/lib/apt/lists/*
COPY --from=composer /usr/bin/composer /usr/local/bin/composer
WORKDIR /app
