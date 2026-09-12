# Columbia - OHTTP relay
# Track Node 24 LTS patch releases; rebuild with --pull. See SELFHOSTING.md.
FROM node:24-alpine
WORKDIR /app
COPY --chmod=0444 server.js ./
ENV PORT=8080
EXPOSE 8080
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD ["node", "-e", "require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
CMD ["node", "--max-http-header-size=16384", "server.js"]
