# Columbia - token issuer (Privacy Pass Attester + Issuer)
# Unlike the relay/commons this service has npm dependencies (blind-RSA), so we do
# a real npm ci against the committed lockfile. Still a small node:alpine image,
# non-root, with a HEALTHCHECK, matching the other services.
# pin by @sha256:<digest> in CI for full reproducibility
FROM node:20.18.1-alpine

WORKDIR /app

# Install deps first (cached layer). --omit=dev: no dev deps in the runtime image.
# npm ci installs EXACTLY what the lockfile pins, so the image is reproducible.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY server.js appattest.js ./

ENV PORT=8080
EXPOSE 8080

# Run as the non-root 'node' user shipped in the base image.
USER node

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["node", "-e", "require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]

CMD ["node", "server.js"]
