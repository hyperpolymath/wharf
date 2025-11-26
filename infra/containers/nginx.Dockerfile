# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>
#
# Wolfi Nginx Container for Project Wharf
# ========================================
# A minimal, hardened reverse proxy / web server:
# - No shell, no package manager at runtime
# - Non-root user (binds to 8080, not 80)
# - Strict security headers enforced
# - JSON logging for observability
#
# The eBPF firewall redirects port 80 -> 8080 transparently.

# -----------------------------------------------------------------------------
# Runtime Stage (Single stage - Chainguard provides pre-hardened base)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/nginx:latest

# Copy our hardened Nginx configuration
COPY infra/config/nginx.conf /etc/nginx/nginx.conf

# Copy CMS-specific rules (WordPress by default)
COPY infra/config/wordpress-rules.conf /etc/nginx/conf.d/default.conf

# Create required directories for non-root operation
# These must exist even though they'll be tmpfs mounts
USER root
RUN mkdir -p /tmp/client_temp \
    && mkdir -p /tmp/proxy_temp \
    && mkdir -p /tmp/fastcgi_temp \
    && mkdir -p /tmp/uwsgi_temp \
    && mkdir -p /tmp/scgi_temp \
    && mkdir -p /var/www/html \
    && chown -R nonroot:nonroot /tmp \
    && chown -R nonroot:nonroot /var/www/html

# SECURITY: Switch to non-root
USER nonroot

# NETWORK: Non-privileged ports (privileged ports require root)
# eBPF firewall handles 80->8080 and 443->8443 redirection
EXPOSE 8080 8443

# HEALTH CHECK
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# ENTRYPOINT: Direct binary execution
CMD ["nginx", "-g", "daemon off;"]
