# Token Vault web UIs on nginx (non-root, port 8080). Build from the repository root:
#   docker build -f deploy/docker/web.Dockerfile --build-arg APP=client     -t token-vault/console .
#   docker build -f deploy/docker/web.Dockerfile --build-arg APP=cms/client -t token-vault/cms-ui .
# At run time, point the proxy at the API:
#   console: API_UPSTREAM=http://server:4000      cms ui: CMS_API_UPSTREAM=http://cms-api:4200
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27-alpine
# Base images are build arguments, e.g. to pull through a registry mirror.
FROM ${NODE_IMAGE} AS build
ARG APP
WORKDIR /src
COPY . .
RUN --mount=type=secret,id=extra_ca,required=false \
    if [ -f /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    test -n "$APP" && \
    npm ci --workspace="$APP" --workspace=client --workspace=shared --ignore-scripts --no-audit --no-fund && \
    npm run build -w "$APP" && \
    mkdir -p /out && cp -r "$APP/dist" /out/html && \
    if [ "$APP" = "client" ]; then cp deploy/docker/nginx/console.conf.template /out/default.conf.template; else cp deploy/docker/nginx/cms.conf.template /out/default.conf.template; fi

FROM ${NGINX_IMAGE}
# Only these variables are substituted into the config (nginx's own $vars stay as they are).
ENV NGINX_ENVSUBST_FILTER="^(API_UPSTREAM|CMS_API_UPSTREAM)$"
COPY --from=build /out/html /usr/share/nginx/html
COPY --from=build /out/default.conf.template /etc/nginx/templates/default.conf.template
COPY deploy/docker/nginx/proxy.inc /etc/nginx/snippets/proxy.inc
EXPOSE 8080
