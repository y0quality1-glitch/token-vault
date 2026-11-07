# Build from the repository root (the SDK lives in sdk/):
#   docker build -f examples/kubernetes/orders-api/Dockerfile -t orders-api:dev .
#
# Stage 1 bundles the service and the Token Vault SDK into one file (the SDK has no
# runtime dependencies), so the runtime image has no node_modules at all.
FROM node:22-alpine AS build
WORKDIR /src
COPY sdk/src sdk/src
COPY shared/src shared/src
COPY examples/kubernetes/orders-api/src examples/kubernetes/orders-api/src
# Behind a TLS-inspecting proxy, pass its CA as an optional build secret (never stored in the image):
#   docker build --secret id=extra_ca,src=/path/to/ca.pem ...
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npx --yes esbuild@0.25.0 examples/kubernetes/orders-api/src/server.ts \
      --bundle --platform=node --target=node22 --format=esm \
      --alias:@token-vault/sdk=./sdk/src/index.ts \
      --outfile=/out/server.mjs

# Stage 2: minimal runtime, non-root, read-only friendly (writes nothing to disk).
FROM node:22-alpine
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=build /out/server.mjs ./server.mjs
# Numeric UID (the image's "node" user), so Kubernetes can verify runAsNonRoot.
USER 1000:1000
EXPOSE 8080
CMD ["node", "server.mjs"]
