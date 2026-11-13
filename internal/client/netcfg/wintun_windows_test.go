package netcfg

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// These tests exercise the loading of the Wintun library on Windows itself.
// They are built into a test program on a development machine
// (GOOS=windows go test -c ./internal/client/netcfg) and run in the Wine
// lab (test/winelab), which first plants an old-style Wintun adapter in the
// registry, the kind Astrill VPN has. All but the first are skipped unless
// an environment variable names that adapter, because they load the library
// into the test process, and one of them does so without the safeguards on
// purpose.

// labDescription marks an adapter planted by the lab. The destructive test
// refuses to run against anything else.
const labDescription = "Lanora lab adapter"

func testLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// onWine reports whether the test is running on Wine rather than Windows.
func onWine() bool {
	return windows.NewLazySystemDLL("ntdll.dll").NewProc("wine_get_version").Find() == nil
}

// completeWineRemoval fills a gap in Wine so that the library's clean-up
// can run to its end there. The clean-up removes an adapter in two calls:
// SetupDiSetClassInstallParamsW to say "remove", then
// SetupDiCallClassInstaller to do it. Wine implements the second (it
// deletes the device) but not the first, which always fails, so on Wine the
// clean-up would stop one step short and remove nothing, with or without
// Lanora's safeguards. Making the first call succeed lets the tests show
// the difference the safeguards make. It does nothing on Windows.
func completeWineRemoval(t *testing.T) {
	if !onWine() {
		return
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("the Wine lab runs the amd64 build")
	}
	proc := setupapi.NewProc("SetupDiSetClassInstallParamsW")
	if err := proc.Find(); err != nil {
		t.Fatal(err)
	}
	returnTrue := []byte{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3} // mov eax, 1; ret
	if err := writeMemory(proc.Addr(), returnTrue); err != nil {
		t.Fatalf("completing Wine's SetupDiSetClassInstallParamsW: %v", err)
	}
	t.Log("running on Wine: SetupDiSetClassInstallParamsW made to succeed, so that the library's clean-up can reach the removal")
}

// onlyTheLabAdapter fails the test unless the named adapter is the lab's
// own and the only old-style Wintun adapter there is. Tests that could
// delete adapters call it first.
func onlyTheLabAdapter(t *testing.T, id string) map[string]legacyDevice {
	devices, _ := legacyWintunDevices()
	dev, ok := devices[id]
	if !ok {
		t.Fatalf("%s is not among the old-style Wintun adapters found: %v", id, describe(devices))
	}
	if len(devices) != 1 || dev.description != labDescription {
		t.Fatalf("refusing to run: this test can delete every old-style Wintun adapter, and found something other than the lab's own: %v", describe(devices))
	}
	return devices
}

func wintunLoaded() bool {
	name, _ := windows.UTF16PtrFromString("wintun.dll")
	var h windows.Handle
	return windows.GetModuleHandleEx(0, name, &h) == nil && h != 0
}

// Blocking and unblocking the two device functions is safe on any machine:
// nothing is loaded and nothing outside this process is touched.
func TestBlockDeviceRemoval(t *testing.T) {
	couldList := func() bool {
		h := listRootNetDevices()
		if h == invalidHandle {
			return false
		}
		procSetupDiDestroyDeviceInfoList.Call(h)
		return true
	}
	if err := procSetupDiGetClassDevsExW.Find(); err != nil {
		t.Fatal(err)
	}
	before := couldList()
	t.Logf("listing ROOT\\NET adapters works before blocking: %v", before)

	release, err := blockDeviceRemoval()
	if err != nil {
		t.Fatalf("blockDeviceRemoval: %v", err)
	}
	if couldList() {
		t.Error("adapters can still be listed while blocked")
	}
	// The removal function must now do nothing and report failure, whatever
	// it is given.
	const difRemove = 0x5
	if r, _, _ := procSetupDiCallClassInstaller.Call(difRemove, 0, 0); r != 0 {
		t.Errorf("SetupDiCallClassInstaller returned %d while blocked", r)
	}
	head := make([]byte, len(stubReturnFalse))
	if err := readMemory(procSetupDiCallClassInstaller.Addr(), head); err != nil || !bytes.Equal(head, stubReturnFalse) {
		t.Errorf("SetupDiCallClassInstaller is not blocked: % x, %v", head, err)
	}

	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if after := couldList(); after != before {
		t.Errorf("listing adapters works = %v after unblocking, was %v before", after, before)
	}
	if err := readMemory(procSetupDiCallClassInstaller.Addr(), head); err != nil || bytes.Equal(head, stubReturnFalse) {
		t.Errorf("SetupDiCallClassInstaller is still blocked after release: % x, %v", head, err)
	}

	// A second round must work the same: the service does this once per
	// start, but nothing should depend on that.
	release, err = blockDeviceRemoval()
	if err != nil {
		t.Fatalf("second blockDeviceRemoval: %v", err)
	}
	if couldList() {
		t.Error("adapters can still be listed while blocked the second time")
	}
	if err := release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

// The load Lanora performs: with an old-style adapter present, the library
// must end up loaded and the adapter must still be there.
func TestGuardedLoadKeepsLegacyAdapters(t *testing.T) {
	id := os.Getenv("LANORA_TEST_LEGACY_ADAPTER")
	if id == "" {
		t.Skip("set LANORA_TEST_LEGACY_ADAPTER to the device ID of an old-style Wintun adapter (for example ROOT\\NET\\0000)")
	}
	before, complete := legacyWintunDevices()
	if _, ok := before[id]; !ok || !complete {
		t.Fatalf("%s is not among the old-style Wintun adapters found: %v (scan complete: %v)", id, describe(before), complete)
	}
	t.Logf("before: %v", describe(before))
	completeWineRemoval(t)

	log, out := testLogger()
	err := loadWintun(log)
	t.Logf("log:\n%s", out.String())
	if err != nil {
		t.Fatalf("loadWintun: %v", err)
	}
	if !wintunLoaded() {
		t.Error("the library is not loaded")
	}
	if !strings.Contains(out.String(), "blocked in this process") {
		t.Error("the load did not go through the safeguards")
	}
	after, _ := legacyWintunDevices()
	t.Logf("after: %v", describe(after))
	for dev := range before {
		if _, ok := after[dev]; !ok {
			t.Errorf("%s was removed", dev)
		}
	}
}

// The control experiment: the same library loaded the ordinary way removes
// the adapter. This is what every other program using Wintun does to
// Astrill, and what the test above shows Lanora not doing.
func TestUnguardedLoadRemovesLegacyAdapters(t *testing.T) {
	id := os.Getenv("LANORA_TEST_DESTROY_LEGACY_ADAPTER")
	if id == "" {
		t.Skip("destructive; only for the lab. It deletes the adapter named in LANORA_TEST_DESTROY_LEGACY_ADAPTER")
	}
	before := onlyTheLabAdapter(t, id)
	completeWineRemoval(t)
	path, err := installWintunDLL()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		t.Fatalf("loading the library: %v", err)
	}
	after, _ := legacyWintunDevices()
	t.Logf("before: %v", describe(before))
	t.Logf("after:  %v", describe(after))
	if _, still := after[id]; still {
		t.Errorf("%s survived an ordinary load of the library; the lab does not reproduce the removal", id)
	}
}

// Each of the two blocks is enough by itself. With only the removal call
// blocked, the clean-up finds the adapter, tries to remove it and fails.
func TestRemovalBlockAloneKeepsLegacyAdapters(t *testing.T) {
	id := os.Getenv("LANORA_TEST_DESTROY_LEGACY_ADAPTER")
	if id == "" {
		t.Skip("only for the lab: it would delete the adapter named in LANORA_TEST_DESTROY_LEGACY_ADAPTER if the block did not hold")
	}
	before := onlyTheLabAdapter(t, id)
	completeWineRemoval(t)
	if err := procSetupDiCallClassInstaller.Find(); err != nil {
		t.Fatal(err)
	}
	remove := &patch{name: "SetupDiCallClassInstaller", addr: procSetupDiCallClassInstaller.Addr()}
	if err := remove.apply(stubReturnFalse); err != nil {
		t.Fatal(err)
	}
	path, err := installWintunDLL()
	if err != nil {
		t.Fatal(err)
	}
	_, loadErr := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err := remove.restore(); err != nil {
		t.Fatal(err)
	}
	if loadErr != nil {
		t.Fatalf("loading the library: %v", loadErr)
	}
	after, _ := legacyWintunDevices()
	t.Logf("before: %v", describe(before))
	t.Logf("after:  %v", describe(after))
	if _, still := after[id]; !still {
		t.Errorf("%s was removed although the removal call was blocked", id)
	}
}

// An adapter running an older Wintun driver: Lanora must stop before
// loading anything, because creating its own adapter would replace that
// driver.
func TestOlderDriverIsRefused(t *testing.T) {
	id := os.Getenv("LANORA_TEST_OLD_DRIVER_ADAPTER")
	if id == "" {
		t.Skip("set LANORA_TEST_OLD_DRIVER_ADAPTER to the device ID of an old-style Wintun adapter with an older driver")
	}
	before, _ := legacyWintunDevices()
	if _, ok := before[id]; !ok {
		t.Fatalf("%s is not among the old-style Wintun adapters found: %v", id, describe(before))
	}
	log, out := testLogger()
	err := loadWintun(log)
	t.Logf("log:\n%s", out.String())
	var old *OlderDriverError
	if !errors.As(err, &old) {
		t.Fatalf("loadWintun = %v, want an OlderDriverError", err)
	}
	t.Logf("message shown to the user: %v", err)
	if wintunLoaded() {
		t.Error("the library was loaded although it would replace another program's driver")
	}
	after, _ := legacyWintunDevices()
	if _, ok := after[id]; !ok {
		t.Errorf("%s was removed", id)
	}
}
