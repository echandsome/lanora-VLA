# Environment for building and looking at the Lanora window on Linux: the
# libraries the UI toolkit needs, a virtual display with software rendering,
# and tools to drive the window and take screenshots. The Go toolchain is
# mounted from the host.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev pkg-config ca-certificates curl jq \
        libx11-dev libx11-xcb-dev libxkbcommon-dev libxkbcommon-x11-dev libxcursor-dev libxfixes-dev \
        libegl1-mesa-dev libgles2-mesa-dev libgl1-mesa-dri \
        xvfb xdotool imagemagick x11-utils fonts-inter fonts-noto-cjk iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
