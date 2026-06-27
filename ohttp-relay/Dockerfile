# Columbia - OHTTP relay
# pin by @sha256:<digest> in CI for full reproducibility
FROM node:20.18.1-alpine
WORKDIR /app
COPY server.js ./
ENV PORT=8080
EXPOSE 8080
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["node", "-e", "require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
CMD ["node", "--max-http-header-size=16384", "server.js"]
