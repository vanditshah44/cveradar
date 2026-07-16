#!/bin/bash
# ssl-init.sh — Get a Let's Encrypt SSL certificate for your domain.
# Run this ONCE before starting the production stack.
#
# Usage: bash scripts/ssl-init.sh yourdomain.com your@email.com

set -euo pipefail

DOMAIN="${1:?Usage: $0 <domain> <email>}"
EMAIL="${2:?Usage: $0 <domain> <email>}"

echo "==> Getting Let's Encrypt certificate for $DOMAIN"

# 1. Start nginx with HTTP-only config so ACME challenge can complete
docker compose -f docker-compose.prod.yml up -d nginx

# 2. Get certificate via Certbot webroot method
docker run --rm \
  -v "$(pwd)/nginx/letsencrypt:/etc/letsencrypt" \
  -v "$(pwd)/nginx/certbot-webroot:/var/www/certbot" \
  certbot/certbot certonly \
    --webroot \
    --webroot-path /var/www/certbot \
    --email "$EMAIL" \
    --agree-tos \
    --no-eff-email \
    -d "$DOMAIN"

echo "==> Certificate obtained. Update nginx/nginx.conf: replace YOUR_DOMAIN with $DOMAIN"
echo "==> Then run: docker compose -f docker-compose.prod.yml up -d --build"
