FROM node:24-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --chown=node:node server.mjs ./server.mjs
COPY --chown=node:node vulnerabilities.mjs ./vulnerabilities.mjs
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD node -e "fetch('http://127.0.0.1:8787/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.mjs"]
