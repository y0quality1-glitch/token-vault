# Token Vault Node services: control plane (server), customer webhook (webhook) and provider
# CMS API (cms/api). Build from the repository root:
#   docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=server  -t token-vault/server .
#   docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=webhook -t token-vault/webhook .
#   docker build -f deploy/docker/service.Dockerfile --build-arg SERVICE=cms/api -t token-vault/cms-api .
#
# Stage 1 installs that service's dependencies and bundles it into one file; the runtime image
# holds only the bundle and its SQL migrations (applied at start-up). Configuration comes from
# environment variables only (see docs/DEPLOYMENT.md); no .env file is read inside the image.
ARG NODE_IMAGE=node:22-alpine
# The base image is a build argument, e.g. to pull through a registry mirror.
FROM ${NODE_IMAGE} AS build
ARG SERVICE
WORKDIR /src
COPY . .
# Behind a TLS-inspecting proxy, pass its CA as an optional build secret (not stored in the image):
#   docker build --secret id=extra_ca,src=/path/to/ca.pem ...
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    test -n "$SERVICE" && \
    npm ci --workspace="$SERVICE" --workspace=shared --ignore-scripts --no-audit --no-fund && \
    npx --yes esbuild@0.25.0 "$SERVICE/src/index.ts" \
      --bundle --platform=node --target=node22 --format=esm \
      --external:pg-native --external:swagger-ui-dist \
      --banner:js="import { createRequire as __tvCreateRequire } from 'node:module'; import { fileURLToPath as __tvFileURLToPath } from 'node:url'; import { dirname as __tvDirname } from 'node:path'; const require = __tvCreateRequire(import.meta.url); const __filename = __tvFileURLToPath(import.meta.url); const __dirname = __tvDirname(__filename);" \
      --outfile=/out/service.mjs && \
    # SQL migrations (server, webhook); the CMS API's TypeORM migrations are bundled.
    if [ -d "$SERVICE/drizzle" ]; then cp -r "$SERVICE/drizzle" /out/drizzle; fi && \
    # The CMS API serves swagger-ui's static files from disk, so it keeps that package.
    if [ "$SERVICE" = "cms/api" ]; then \
      mkdir -p /out/node_modules && \
      for p in swagger-ui-dist; do cp -r "$(node -p "require('path').dirname(require.resolve('$p/package.json', { paths: ['$SERVICE'] }))")" /out/node_modules/; done; \
    fi

FROM ${NODE_IMAGE}
ENV NODE_ENV=production MIGRATIONS_DIR=/app/drizzle
WORKDIR /app
COPY --from=build /out/ ./
# Numeric UID (the image's "node" user), so Kubernetes can verify runAsNonRoot.
USER 1000:1000
CMD ["node", "service.mjs"]
