FROM node:22-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    APPIMAGE_EXTRACT_AND_RUN=1 \
    PATH=/root/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    file \
    libayatana-appindicator3-dev \
    librsvg2-dev \
    libssl-dev \
    libwebkit2gtk-4.1-dev \
    libxdo-dev \
    patchelf \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal

WORKDIR /workspace
COPY . /workspace
RUN --mount=type=cache,target=/root/.npm \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/workspace/installer/src-tauri/target \
    cd installer \
    && npm ci \
    && npm run tauri:build -- --bundles deb,appimage \
    && mkdir -p /actium-installer-artifacts \
    && cp src-tauri/target/release/bundle/deb/*.deb /actium-installer-artifacts/ \
    && cp src-tauri/target/release/bundle/appimage/*.AppImage /actium-installer-artifacts/
