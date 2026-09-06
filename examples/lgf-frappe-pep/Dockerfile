# Generic OxDeAI PEP sidecar OCI image
# Implementation source currently comes from the LGF/Frappe example package,
# but all runtime credentials and deployment-specific settings remain external.
#
# Build context must be the repo root:
#   docker build -f examples/lgf-frappe-pep/Dockerfile .
#
# Place a .dockerignore at the repo root to exclude .env, .git, etc.
# The .dockerignore at examples/lgf-frappe-pep/ is NOT used when the
# build context is the repo root.

FROM node:20-alpine AS build
RUN corepack enable && corepack prepare pnpm@10.34.5 --activate
WORKDIR /app

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY tsconfig.base.json ./
COPY packages/core/package.json packages/core/
COPY packages/guard/package.json packages/guard/
COPY examples/lgf-frappe-pep/package.json examples/lgf-frappe-pep/

RUN pnpm install --frozen-lockfile

COPY packages/core/ packages/core/
COPY packages/guard/ packages/guard/
COPY examples/lgf-frappe-pep/src/ examples/lgf-frappe-pep/src/
COPY examples/lgf-frappe-pep/tsconfig.json examples/lgf-frappe-pep/

RUN pnpm --filter @oxdeai/core build && \
    pnpm --filter @oxdeai/guard build && \
    pnpm --filter @oxdeai/example-lgf-frappe-pep build

FROM node:20-alpine
RUN corepack enable && corepack prepare pnpm@10.34.5 --activate
WORKDIR /app

LABEL org.opencontainers.image.title="OxDeAI PEP Sidecar"
LABEL org.opencontainers.image.description="Generic OxDeAI PEP sidecar OCI image built from the LGF/Frappe example runtime with runtime-injected configuration."
LABEL org.opencontainers.image.source="https://github.com/oxdeai/oxdeai"

COPY --from=build /app/pnpm-lock.yaml /app/pnpm-workspace.yaml /app/package.json ./
COPY --from=build /app/packages/core/package.json packages/core/package.json
COPY --from=build /app/packages/core/dist/ packages/core/dist/
COPY --from=build /app/packages/guard/package.json packages/guard/package.json
COPY --from=build /app/packages/guard/dist/ packages/guard/dist/
COPY --from=build /app/examples/lgf-frappe-pep/package.json examples/lgf-frappe-pep/
COPY --from=build /app/examples/lgf-frappe-pep/dist/ examples/lgf-frappe-pep/dist/
COPY --from=build /app/node_modules/ node_modules/
COPY --from=build /app/packages/core/node_modules/ packages/core/node_modules/
COPY --from=build /app/packages/guard/node_modules/ packages/guard/node_modules/
COPY --from=build /app/examples/lgf-frappe-pep/node_modules/ examples/lgf-frappe-pep/node_modules/

ENV OXDEAI_MODE=enforce
ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1

USER node

CMD ["node", "examples/lgf-frappe-pep/dist/src/server.js"]
