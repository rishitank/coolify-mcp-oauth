FROM node:22-alpine

WORKDIR /app

# Install deps first for better layer caching. No package-lock.json is
# committed to the repo (see .gitignore) — `npm install` resolves against
# the semver ranges in package.json, same as local development.
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Pre-install the real Coolify MCP server globally so each session's
# spawn is a fast local exec instead of an `npx` registry round-trip —
# see src/env.js (COOLIFY_MCP_COMMAND/ARGS) for how this is wired in.
RUN npm install -g @masonator/coolify-mcp

COPY src ./src

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/data \
    COOLIFY_MCP_COMMAND=coolify-mcp \
    COOLIFY_MCP_ARGS=

VOLUME ["/data"]
EXPOSE 3000

CMD ["node", "src/index.js"]
