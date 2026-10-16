# IPA Pocket 0.3.4 — Anisette login fix with UDID-aware SideSign build.
# The Windows 7 PC is used only as a browser; signing runs in the cloud container.
FROM swift:6.0.3-noble

ENV DEBIAN_FRONTEND=noninteractive
# Make the Unicorn headers and library visible to SwiftPM/clang link steps.
ENV LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu:/usr/lib
ENV CPATH=/usr/local/include:/usr/local/include/unicorn
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg git wget tar unzip \
    build-essential binutils gnupg2 libc6-dev libcurl4-openssl-dev \
    libedit2 libsqlite3-0 libstdc++-13-dev libxml2-dev libz3-dev \
    libdeflate-dev pkg-config tzdata zlib1g-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

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

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js ./
COPY public ./public
ENV NODE_ENV=production
EXPOSE 3000
CMD ["npm", "start"]
