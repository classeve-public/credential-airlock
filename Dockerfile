# syntax=docker/dockerfile:1
#
# Credential Airlock container image.
#   - multi-stage: a full node image builds, a distroless image runs
#   - runtime image is distroless + NON-ROOT (uid 65532), no shell, no package manager
#   - in a container the sealer is the passphrase sealer (DPAPI/Keychain are
#     host-OS bound); provide it via AIRLOCK_PASSPHRASE_FILE (a Docker/K8s secret)
#
# See docs/DEPLOY.md for the loopback/sidecar networking model.

# ---- build stage ----------------------------------------------------------
FROM node:22-bookworm-slim AS build
WORKDIR /app
ENV NODE_ENV=development
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
# Drop dev dependencies so only the pinned runtime dep ships in the final image.
RUN npm prune --omit=dev

# ---- runtime stage (distroless, non-root) ---------------------------------
FROM gcr.io/distroless/nodejs22-debian12:nonroot AS runtime
WORKDIR /app
LABEL org.opencontainers.image.title="Credential Airlock" \
      org.opencontainers.image.description="Self-hosted, OS-sealed credential firewall for AI agents." \
      org.opencontainers.image.vendor="Classeve" \
      org.opencontainers.image.authors="Classeve" \
      org.opencontainers.image.source="https://github.com/classeve-public/credential-airlock" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV NODE_ENV=production \
    AIRLOCK_NO_OPEN=1 \
    AIRLOCK_HOME=/data
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY public ./public
# /data holds the sealed vault + CA + audit. Mount a volume; it must be writable
# by uid 65532 (see docker-compose.yml's init step).
VOLUME ["/data"]
# Informational only — the proxy binds loopback; agents share this netns.
EXPOSE 7788 7800
ENTRYPOINT ["/nodejs/bin/node", "/app/dist/index.js"]
CMD ["start"]
