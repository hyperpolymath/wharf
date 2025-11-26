# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Wolfi PHP Container for Project Wharf
# ======================================
# This is NOT a standard PHP image. It is stripped to "race weight":
# - No shell (sh, bash, zsh)
# - No package manager at runtime
# - Non-root user
# - Hardened PHP configuration
#
# Attack surface: Minimal. If a hacker breaks in, they can't run commands.

# -----------------------------------------------------------------------------
# STAGE 1: Builder (The Factory)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS builder

# Install PHP and required extensions for CMS compatibility
RUN apk add --no-cache \
    php-8.3 \
    php-8.3-fpm \
    php-8.3-opcache \
    php-8.3-mysqli \
    php-8.3-pdo \
    php-8.3-pdo_mysql \
    php-8.3-pdo_pgsql \
    php-8.3-mysqlnd \
    php-8.3-mbstring \
    php-8.3-gd \
    php-8.3-xml \
    php-8.3-simplexml \
    php-8.3-dom \
    php-8.3-curl \
    php-8.3-zip \
    php-8.3-intl \
    php-8.3-bcmath \
    php-8.3-sodium \
    php-8.3-redis \
    php-8.3-imagick \
    php-8.3-exif \
    php-8.3-fileinfo \
    && rm -rf /var/cache/apk/*

# Harden php.ini at build time
RUN set -eux; \
    # Hide PHP version from headers
    sed -i 's/expose_php = On/expose_php = Off/' /etc/php83/php.ini; \
    # Increase memory for CMS workloads
    sed -i 's/memory_limit = 128M/memory_limit = 256M/' /etc/php83/php.ini; \
    # Disable error display (log only)
    sed -i 's/display_errors = On/display_errors = Off/' /etc/php83/php.ini; \
    # Block remote file inclusion attacks
    sed -i 's/allow_url_fopen = On/allow_url_fopen = Off/' /etc/php83/php.ini; \
    sed -i 's/allow_url_include = On/allow_url_include = Off/' /etc/php83/php.ini; \
    # Disable dangerous functions
    echo "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source" >> /etc/php83/php.ini; \
    # OPcache for performance
    echo "opcache.enable=1" >> /etc/php83/php.ini; \
    echo "opcache.memory_consumption=128" >> /etc/php83/php.ini; \
    echo "opcache.interned_strings_buffer=8" >> /etc/php83/php.ini; \
    echo "opcache.max_accelerated_files=10000" >> /etc/php83/php.ini; \
    echo "opcache.revalidate_freq=0" >> /etc/php83/php.ini; \
    echo "opcache.validate_timestamps=0" >> /etc/php83/php.ini

# -----------------------------------------------------------------------------
# STAGE 2: Runtime (The Yacht)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/php:latest-fpm

# Copy hardened configuration
COPY --from=builder /etc/php83/php.ini /etc/php83/php.ini

# Copy our custom FPM pool configuration
COPY infra/config/php-fpm.conf /etc/php83/php-fpm.d/www.conf

# Create directories for WordPress compatibility
# These will be mounted as volumes
RUN mkdir -p /var/www/html \
    && mkdir -p /var/www/html/wp-content/uploads \
    && mkdir -p /var/www/html/wp-content/cache

# SECURITY: Run as non-root (uid 65532 is standard nonroot in distroless)
USER nonroot

# NETWORK: FastCGI port
EXPOSE 9000

# HEALTH CHECK
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD php-fpm83 -t || exit 1

# ENTRYPOINT: Just the FPM binary, no wrapper scripts
CMD ["php-fpm83", "-F"]
