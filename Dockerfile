# IPA Pocket 0.3.6 — use a local Anisette V3 server rather than public servers.
# The sidecar binary comes from the upstream Docker image; no TLS verification is disabled.
FROM dadoum/anisette-v3-server:latest AS anisette-v3

# Configure a verified system CA trust store for normal HTTPS requests.
# The Windows 7 PC is used only as a browser; signing runs in the cloud container.
FROM swift:6.0.3-noble

ENV DEBIAN_FRONTEND=noninteractive
# Make the Unicorn headers and library visible to SwiftPM/clang link steps.
ENV LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib
ENV CPATH=/usr/local/include:/usr/local/include/unicorn
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg git wget tar unzip \
    build-essential binutils gnupg2 libc6-dev libcurl4-openssl-dev \
    libedit2 libsqlite3-0 libstdc++-13-dev libxml2-dev libz3-dev libplist-2.0-4 \
    libdeflate-dev pkg-config tzdata zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Refresh the OS CA bundle and point curl/OpenSSL-based clients at the same verified trust store.
# Do not disable TLS verification: that would expose Apple sign-in traffic to interception.
RUN update-ca-certificates --fresh \
    && test -s /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs \
    CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# Node.js 22 (web server runtime) alongside the Swift runtime required by SideSign.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# SideSign's Linux build needs the Unicorn static library used by its Anisette component.
RUN mkdir -p /tmp/unicorn-dist \
    && curl -fL https://github.com/mahee96/unicorn/releases/latest/download/unicorn-linux-x86_64.tar.gz -o /tmp/unicorn.tar.gz \
    && tar -xzf /tmp/unicorn.tar.gz -C /tmp/unicorn-dist \
    && UHEADER="$(find /tmp/unicorn-dist -type f -name unicorn.h -print -quit)" \
    && ULIB="$(find /tmp/unicorn-dist -type f -name libunicorn.a -print -quit)" \
    && test -n "$UHEADER" && test -n "$ULIB" \
    && mkdir -p /usr/local/include/unicorn /usr/local/lib \
    && cp -a "$(dirname "$UHEADER")"/. /usr/local/include/unicorn/ \
    && cp "$ULIB" /usr/local/lib/libunicorn.a \
    && cp "$ULIB" /usr/lib/x86_64-linux-gnu/libunicorn.a \
    && cp "$ULIB" /usr/lib/libunicorn.a \
    && ranlib /usr/local/lib/libunicorn.a \
    && ranlib /usr/lib/x86_64-linux-gnu/libunicorn.a \
    && ranlib /usr/lib/libunicorn.a \
    && test -s /usr/lib/x86_64-linux-gnu/libunicorn.a \
    && nm -g --defined-only /usr/lib/x86_64-linux-gnu/libunicorn.a | grep -Eq "[[:space:]]uc_open$" \
    && nm -g --defined-only /usr/lib/x86_64-linux-gnu/libunicorn.a | grep -Eq "[[:space:]]uc_emu_start$" \
    && ldconfig \
    && rm -rf /tmp/unicorn-dist /tmp/unicorn.tar.gz

# Build SideSign CLI from its open-source repo for Linux.
RUN git clone --depth 1 https://github.com/SideStore/SideSign.git /opt/SideSign \
    && cd /opt/SideSign \
    && swift build -c release --product sidesign \
    && install -m 0755 ./.build/release/sidesign /usr/local/bin/sidesign \
    && rm -rf /opt/SideSign

# The upstream Anisette V3 service listens on 6969 internally. It is only accessed
# over loopback by SideSign; it is not exposed publicly by Render.
COPY --from=anisette-v3 /opt/anisette-v3-server /usr/local/bin/anisette-v3-server
RUN mkdir -p /home/Alcoholic/.config/anisette-v3/lib /home/Alcoholic/.config/anisette-v3/provisioning /opt/anisette-v3/provisioning \
    && chmod -R 700 /home/Alcoholic/.config/anisette-v3

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY start.sh ./start.sh
COPY public ./public
ENV NODE_ENV=production
EXPOSE 3000
CMD ["sh", "/app/start.sh"]
