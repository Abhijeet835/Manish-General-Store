# =============================================================================
# Dockerfile — Manish General Store API
# Base: node:20-alpine (official lightweight Node.js image)
# =============================================================================

# ── Stage: Single-stage development image ─────────────────────────────────────
# We use the Alpine variant to keep the final image small (~50 MB vs ~350 MB
# for the full Debian-based image), which matters for deployment speed and
# attack surface.
FROM node:20-alpine

# ── System-level dependencies ─────────────────────────────────────────────────
# Install bash and other lightweight utilities that nodemon may need on Alpine.
# --no-cache avoids storing the index locally, keeping the layer lean.
RUN apk add --no-cache bash

# ── Working directory ──────────────────────────────────────────────────────────
# All subsequent RUN / COPY / CMD instructions operate relative to this path.
# Using /usr/src/app is the conventional Node.js working directory inside Docker.
WORKDIR /usr/src/app

# ── Layer-cache optimisation: install dependencies FIRST ──────────────────────
# Docker builds layers in order. By copying ONLY the package manifests before
# the rest of the source code, we ensure that "npm install" is only re-run when
# package.json or package-lock.json actually changes — not on every code edit.
COPY package*.json ./

# Install ALL dependencies (including devDependencies like nodemon) because
# this Dockerfile targets the development environment.
# --legacy-peer-deps is a safety net for minor peer-dep version conflicts.
RUN npm install --legacy-peer-deps

# ── Application source code ────────────────────────────────────────────────────
# Copy the rest of the project into the container AFTER npm install so that
# source-code changes don't invalidate the npm install cache layer above.
COPY . .

# ── Networking ────────────────────────────────────────────────────────────────
# Document that the application inside the container listens on port 5000.
# This does NOT publish the port to the host — that is handled in docker-compose.
EXPOSE 5000

# ── Default startup command ────────────────────────────────────────────────────
# "npm run dev" executes nodemon, which watches for file changes and
# auto-restarts the server — essential for a smooth development loop.
# NOTE: In production, override this with CMD ["npm", "start"] or a dedicated
#       production Dockerfile stage that omits devDependencies entirely.
CMD ["npm", "run", "dev"]