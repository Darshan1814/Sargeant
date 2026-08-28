#!/usr/bin/env bash
#
# offline-bundle.sh — build an air-gapped deployment bundle for ULPF.
#
# On an INTERNET-CONNECTED machine this pulls every container image the stack
# needs, saves them to a single tarball, and packages the source. Copy the
# resulting bundle to the air-gapped network, load the images, and `docker
# compose up` with no registry access required.
#
# Usage:
#   ./scripts/offline-bundle.sh            # produces dist/ulpf-airgap-bundle.tar.gz
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
IMAGES_TAR="${DIST}/ulpf-images.tar"
BUNDLE="${DIST}/ulpf-airgap-bundle.tar.gz"

# Images referenced by docker-compose.yml. Keep in sync when versions change.
IMAGES=(
  "opensearchproject/opensearch:2.13.0"
  "opensearchproject/opensearch-dashboards:2.13.0"
  "prom/prometheus:v2.52.0"
  "grafana/grafana:10.4.3"
  "bitnami/kafka:3.7"
  "minio/minio:RELEASE.2024-06-13T22-53-53Z"
  "clickhouse/clickhouse-server:24.3"
  "python:3.11-slim"   # backend/consumer base image
  "node:20-alpine"     # frontend build base (adjust if your Dockerfile differs)
  "nginx:alpine"       # frontend serve base
)

mkdir -p "${DIST}"

echo "==> Pulling ${#IMAGES[@]} images…"
for img in "${IMAGES[@]}"; do
  echo "    docker pull ${img}"
  docker pull "${img}"
done

echo "==> Saving images to ${IMAGES_TAR} (this can be several GB)…"
docker save -o "${IMAGES_TAR}" "${IMAGES[@]}"

echo "==> Packaging source + images into ${BUNDLE}…"
tar -C "${ROOT}" \
    --exclude='./dist' \
    --exclude='./**/.venv' \
    --exclude='./**/node_modules' \
    --exclude='./**/__pycache__' \
    -czf "${BUNDLE}" \
    backend frontend parsers ocsf prometheus grafana \
    docker-compose.yml README.md scripts \
    "$(basename "${DIST}")/$(basename "${IMAGES_TAR}")"

rm -f "${IMAGES_TAR}"

cat <<EOF

==> Done: ${BUNDLE}

On the AIR-GAPPED host:
  1. tar -xzf ulpf-airgap-bundle.tar.gz
  2. docker load -i dist/ulpf-images.tar
  3. docker compose up            # no registry access needed
EOF
