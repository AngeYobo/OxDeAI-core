# OxDeAI PEP runtime for LGF Frappe Helpdesk PoC
# No secrets baked in — all credentials injected at runtime.
#
# Build context must be the repo root:
#   docker build -f examples/lgf-frappe-pep/Dockerfile .
#
# Place a .dockerignore at the repo root to exclude .env, .git, etc.
# The .dockerignore at examples/lgf-frappe-pep/ is NOT used when the
# build context is the repo root.

# ── Stage 1: build ───────────────────────────────────────────────────────────
FROM node:20-alpine AS build
RUN corepack enable && corepack prepare pnpm@9.12.2 --activate
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

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM node:20-alpine
RUN corepack enable && corepack prepare pnpm@9.12.2 --activate
WORKDIR /app

COPY --from=build /app/pnpm-lock.yaml /app/pnpm-workspace.yaml /app/package.json ./
COPY --from=build /app/packages/core/package.json /app/packages/core/dist/ packages/core/
COPY --from=build /app/packages/guard/package.json /app/packages/guard/dist/ packages/guard/
COPY --from=build /app/examples/lgf-frappe-pep/package.json examples/lgf-frappe-pep/
COPY --from=build /app/examples/lgf-frappe-pep/dist/ examples/lgf-frappe-pep/dist/
COPY --from=build /app/node_modules/ node_modules/
COPY --from=build /app/packages/core/node_modules/ packages/core/node_modules/
COPY --from=build /app/packages/guard/node_modules/ packages/guard/node_modules/
COPY --from=build /app/examples/lgf-frappe-pep/node_modules/ examples/lgf-frappe-pep/node_modules/

ENV OXDEAI_MODE=enforce
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:3000/healthz || exit 1

CMD ["node", "examples/lgf-frappe-pep/dist/src/server.js"]
