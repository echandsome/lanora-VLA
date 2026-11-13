# Wintun

These are the unmodified, signed `wintun.dll` binaries from the official
Wintun 0.14.1 release (<https://www.wintun.net/>, `wintun-0.14.1.zip`,
SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`).
They are embedded into the Windows client, which uses them only through the
documented Wintun API, as `LICENSE.txt` in this directory requires.

Do not replace them with a newer release without reading
`docs/ARCHITECTURE.md` ("Coexisting with Astrill VPN") first: the driver
version inside the DLL matters. 0.14.1 carries driver 0.14.0.0, the same one
Astrill VPN installs, so loading it never replaces the driver Astrill is
using.

Three things describe exactly this release and must be looked at again if
the files change:

- the file hashes in `../wintun_driver_test.go`;
- `embeddedDriver` in `../wintun_driver.go` (the driver's date and version,
  from `DriverVer` in the release's `wintun.inf`), which decides whether
  another program's adapter counts as running an older driver;
- the way the library is loaded in `../wintun_windows.go`, which relies on
  the library's start-up clean-up working through `SetupDiGetClassDevsExW`
  and `SetupDiCallClassInstaller`, as it does in this release's source
  (`api/main.c`, `api/adapter_win7.h`). `make winelab` checks that against
  the binary.
