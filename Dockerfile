# The briq credential gateway. Node, one dependency (@peculiar/x509, for the certificates), the
# CA on a volume at /data.
FROM node:24-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-fund --no-audit && npm cache clean --force
COPY src ./src
ENV GATEWAY_PORT=3128 GATEWAY_STATE_DIR=/data NODE_ENV=production
EXPOSE 3128
CMD ["node", "src/index.js"]
