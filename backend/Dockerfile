# --- Stage 1: Build ---
FROM node:26-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# --- Stage 2: Runtime ---
FROM node:26-alpine

# Applique les correctifs de sécurité des paquets système (OpenSSL, zlib...) publiés depuis la construction de
# l'image de base : le tag node:24-alpine peut être en retard sur les correctifs Alpine. Compromis assumé : le build
# dépend de l'état des dépôts Alpine au moment où il tourne ; la reproductibilité est obtenue en déployant l'image
# par DIGEST (voir taskvault-platform), pas en reconstruisant.
RUN apk upgrade --no-cache

# Bonne pratique sécurité : ne jamais tourner en root dans le conteneur
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /app ./

# Réduction de la surface d'attaque : npm n'est nécessaire qu'au build (stage builder),
# pas à l'exécution. On le retire du stage final pour éliminer ses propres
# dépendances vulnérables (brace-expansion, tar, undici) de l'image livrée.
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx \
    && rm -rf /opt/yarn-v*

USER appuser

EXPOSE 3000

CMD ["node", "index.js"]
