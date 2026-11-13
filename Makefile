# Lanora build.
#
#   make build     server, headless client and load generator for this machine
#   make windows   Lanora.exe (the Windows app) and lanora-cli.exe
#   make test      unit and in-process end-to-end tests
#   make lab       the container network lab (needs Docker)
#   make winelab   the Windows builds under Wine, in a container (needs Docker)
#   make docker    the server container image
#   make all       build + windows
#
# Every binary is pure Go and statically linked; the Windows ones are
# cross-compiled, so no Windows machine or C compiler is needed to build.

VERSION ?= 1.0.0
GO      ?= go
LDFLAGS := -s -w -X lanora/internal/version.Version=$(VERSION)
BUILD   := CGO_ENABLED=0 $(GO) build -trimpath
DIST    := dist

# The resource compiler that puts the icon, manifest and version information
# into the Windows executable. Pinned so builds are repeatable.
WINRES  := $(GO) run github.com/tc-hib/go-winres@v0.3.3

.PHONY: all build windows icons test test-race lab winelab ui-shots docker vet fmt clean

all: build windows

build:
	$(BUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/lanora-server ./cmd/lanora-server
	$(BUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/lanora-cli ./cmd/lanora-cli
	$(BUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/lanora-bench ./cmd/lanora-bench

# The Windows app. "-H windowsgui" keeps a console window from opening with
# it. SERVER, if given, becomes the server address the app starts with, so
# users only have to type a room ID and password:
#     make windows SERVER='https://lan.example.com'
windows: icons
	$(WINRES) make --in build/windows/winres.json --out cmd/lanora/rsrc --arch amd64,arm64 \
		--product-version $(VERSION).0 --file-version $(VERSION).0
	GOOS=windows GOARCH=amd64 $(BUILD) -ldflags "-H windowsgui $(LDFLAGS) -X lanora/internal/client/settings.DefaultServer=$(SERVER)" \
		-o $(DIST)/Lanora.exe ./cmd/lanora
	GOOS=windows GOARCH=arm64 $(BUILD) -ldflags "-H windowsgui $(LDFLAGS) -X lanora/internal/client/settings.DefaultServer=$(SERVER)" \
		-o $(DIST)/Lanora-arm64.exe ./cmd/lanora
	GOOS=windows GOARCH=amd64 $(BUILD) -ldflags "$(LDFLAGS)" -o $(DIST)/lanora-cli.exe ./cmd/lanora-cli

# Regenerate the icon files from the logo's geometry.
icons:
	$(GO) run ./build/windows/genicon build/windows
	cp build/windows/icon.ico cmd/lanora/icon.ico

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Real kernel networking: a server, two NAT routers and clients in
# containers. See test/netlab/lab.sh.
lab: build
	test/netlab/lab.sh

# The Windows builds under Wine: above all, the real wintun.dll loaded
# against a planted adapter of the kind Astrill VPN has, with and without
# Lanora's safeguards. See test/winelab/lab.sh.
winelab:
	test/winelab/lab.sh

# Screenshots of every screen of the window, taken on a virtual display.
ui-shots:
	test/uilab/shots.sh $(DIST)/ui-shots light
	test/uilab/shots.sh $(DIST)/ui-shots dark

docker:
	docker build --build-arg VERSION=$(VERSION) -t lanora-server:$(VERSION) -t lanora-server:latest .

vet:
	$(GO) vet ./...
	GOOS=windows GOARCH=amd64 $(GO) vet ./...
	GOOS=windows GOARCH=arm64 $(GO) vet ./...

fmt:
	gofmt -l -w cmd internal web build

clean:
	rm -rf $(DIST) cmd/lanora/*.syso
