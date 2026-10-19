# ==============================================================================
# CloudSentinel Vulnerable Demo Application - Dockerfile
# Base Image: Official Node.js 22 LTS Alpine (Hardened Container Runtime)
# 
# Security Design Note:
# The container runtime itself is intentionally hardened with best practices
# (non-root execution, minimal footprint, no exposed credentials).
# The target SAST vulnerability resides exclusively in the application source code
# (src/insecure-demo.js) to accurately demonstrate code-level SAST gate blocking.
# ==============================================================================

FROM node:22-alpine AS runtime

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000

# Install minimal system dependencies & create app directory
WORKDIR /app

# Ensure proper ownership of working directory for non-root user
RUN chown -R node:node /app

# Copy dependency manifests first for layer caching
COPY --chown=node:node package*.json ./

# Switch to non-root user (UID/GID 1000 - node)
USER node

# Install strictly production dependencies
RUN npm ci --omit=dev --ignore-scripts

# Copy application source code and public assets with non-root ownership
COPY --chown=node:node src/ ./src/
COPY --chown=node:node public/ ./public/

# Expose non-privileged HTTP application port
EXPOSE 3000

# Health check specification for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:3000/health || exit 1

# Start application server
CMD ["node", "src/app.js"]
