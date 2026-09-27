# ==========================================
# Stage 1: Build Stage
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency definitions
COPY package*.json tsconfig.json ./

# Install all dependencies (including devDependencies for building)
RUN npm ci

# Copy source code and scripts
COPY src ./src
COPY scripts ./scripts

# Build TypeScript to JavaScript
RUN npm run build

# ==========================================
# Stage 2: Production Runtime Stage
# ==========================================
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy package files and install only production dependencies
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy compiled JavaScript and assets from builder stage
COPY --from=builder /app/dist ./dist

# Create data directory for metadata persistence
RUN mkdir -p /app/data && chown -R node:node /app

# Switch to unprivileged user for security
USER node

# Expose default API Gateway port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Start the Gateway application
CMD ["node", "dist/index.js"]
