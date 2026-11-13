# Wine on a virtual display, for running the Windows builds of Lanora on a
# Linux development machine. See lab.sh.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        wine wine64 libwine fonts-wine xvfb xauth xdotool ca-certificates curl jq procps \
    && rm -rf /var/lib/apt/lists/*
ENV WINEDEBUG=-all WINEPREFIX=/wine WINEARCH=win64 DISPLAY=:99
