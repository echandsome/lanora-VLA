package netcfg

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Loading wintun.dll without harming another program's adapter
//
// Wintun's library has a side effect that matters a great deal here. When it
// is loaded into a process, its DllMain removes every Wintun adapter that
// was created the old way: device nodes under ROOT\NET with the hardware ID
// "Wintun" (AdapterCleanupLegacyDevices in Wintun's api/adapter.c). Adapters
// made by the library itself live under SWD\Wintun and are left alone, so
// between programs that all use the library this is harmless.
//
// Astrill VPN is not such a program. It creates its permanent "Astrill VPN"
// adapter with OpenVPN's tapctl tool, which makes exactly that kind of old
// device node. A program that loads wintun.dll with administrator rights
// therefore deletes Astrill's adapter, and Astrill can no longer connect
// until it is repaired. That is how other Wintun-based VPN tools break
// Astrill.
//
// Lanora must not do that. When (and only when) such adapters exist on the
// machine, the library is loaded with three safeguards:
//
//  1. The clean-up cannot find or remove anything. It works through two
//     Windows functions: SetupDiGetClassDevsExW to list the adapters and
//     SetupDiCallClassInstaller to remove each one. For the few
//     milliseconds the load takes, both are made to fail inside this
//     process, and that is confirmed by calling the first one before the
//     library is loaded. The library is not modified; nothing outside this
//     process is affected; both functions are put back, and checked,
//     afterwards. See blockDeviceRemoval.
//
//  2. The load runs on a thread that, for its duration, impersonates a copy
//     of the process's token with the Administrators group disabled and
//     every privilege stripped, so that a removal attempt would also lack
//     the rights for it. See withoutAdminRights.
//
//  3. The result is checked rather than assumed: the old-style Wintun
//     adapters present before the load must all still be present after it.
//
// If the first safeguard cannot be put in place, the library is not loaded.
//
// The library has a second way of disturbing such a program: when it
// creates an adapter and finds an older Wintun driver installed, it replaces
// that driver for the whole machine. The driver inside the library Lanora
// carries is the same version Astrill installs, so there is normally nothing
// to replace; if an old-style adapter is found running an older driver,
// Lanora stops and says so instead of replacing it. See OlderDriverError.

// LegacyAdapterError reports that loading the Wintun library removed
// another program's network adapter in spite of the safeguards.
type LegacyAdapterError struct {
	Removed []string // descriptions of the adapters that disappeared
}

func (e *LegacyAdapterError) Error() string {
	return fmt.Sprintf("While starting, the network driver library removed another program's virtual adapter (%s). "+
		"Lanora's safeguard against this did not work on this computer. "+
		"If the adapter belonged to Astrill VPN, restore it with Astrill's Help > Repair (or reinstall Astrill), "+
		"and please report this to the Lanora developer; do not connect with Lanora again until it is fixed.",
		strings.Join(e.Removed, ", "))
}

// OlderDriverError reports that another program's adapter runs an older
// Wintun driver than the one Lanora carries, which the Wintun library would
// replace.
type OlderDriverError struct {
	Adapter string // description of the adapter
	Version string // its driver's version, or "" when it could not be read
}

func (e *OlderDriverError) Error() string {
	found := "a version of the Wintun network driver that Lanora could not identify"
	if e.Version != "" {
		found = "version " + e.Version + " of the Wintun network driver"
	}
	return fmt.Sprintf("Another program's virtual adapter (%s) uses %s. Lanora uses version %s and would have to replace "+
		"the other program's driver to start, so it did not connect. Update the other program to its current version "+
		"(for Astrill VPN: install the latest Astrill), restart the computer and try again.",
		e.Adapter, found, embeddedDriver)
}

var (
	wintunOnce sync.Once
	wintunErr  error

	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")

	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procFlushInstructionCache = kernel32.NewProc("FlushInstructionCache")

	setupapi                         = windows.NewLazySystemDLL("setupapi.dll")
	procSetupDiGetClassDevsExW       = setupapi.NewProc("SetupDiGetClassDevsExW")
	procSetupDiCallClassInstaller    = setupapi.NewProc("SetupDiCallClassInstaller")
	procSetupDiDestroyDeviceInfoList = setupapi.NewProc("SetupDiDestroyDeviceInfoList")
)

// netClass is GUID_DEVCLASS_NET, the device class of network adapters.
var netClass = windows.GUID{
	Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce,
	Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18},
}

const (
	disableMaxPrivilege = 0x1 // DISABLE_MAX_PRIVILEGE
	invalidHandle       = ^uintptr(0)

	enumRootNet  = `SYSTEM\CurrentControlSet\Enum\ROOT\NET`
	classKeys    = `SYSTEM\CurrentControlSet\Control\Class\`
	networkConns = `SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\`
)

// ensureWintun makes the Wintun library available to this process. It runs
// once; later calls return the first result.
func ensureWintun(log *slog.Logger) error {
	wintunOnce.Do(func() { wintunErr = loadWintun(log) })
	return wintunErr
}

func loadWintun(log *slog.Logger) error {
	path, err := installWintunDLL()
	if err != nil {
		return err
	}
	// Loaded by full path; anything it needs in turn comes from the system
	// directory only. The Wintun Go binding later asks for "wintun.dll" by
	// name, looking in the application directory first. It has to be given
	// this same module: a second copy would run its DllMain, and with it
	// the clean-up, when nothing is guarding against it any more. So the
	// binding's request is made here too, while the safeguards are still
	// in place, and must come back with the module just loaded.
	load := func() error {
		module, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
		if err != nil {
			return err
		}
		byName, err := windows.LoadLibraryEx("wintun.dll", 0,
			windows.LOAD_LIBRARY_SEARCH_APPLICATION_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
		if err != nil {
			return fmt.Errorf("finding the library by name: %w", err)
		}
		if byName != module {
			return errors.New("another copy of wintun.dll on this computer would be used instead of Lanora's own")
		}
		return nil
	}

	before, complete := legacyWintunDevices()
	if len(before) == 0 && complete {
		// Nothing on this machine for the library to remove: this is an
		// ordinary program loading an ordinary library.
		log.Info("loading the Wintun library; there are no old-style Wintun adapters to protect", "path", path)
		if err := load(); err != nil {
			return fmt.Errorf("loading the network driver library: %w", err)
		}
		return nil
	}
	names := describe(before)
	log.Info("old-style Wintun adapters are present; loading the Wintun library without letting it remove them",
		"adapters", names, "registry_scan_complete", complete, "path", path)

	// The library would replace an older driver under the other program.
	for _, d := range sorted(before) {
		if !d.bound {
			continue // no driver on it: nothing of it to replace
		}
		v, known := d.driver()
		if !known || v.olderThan(embeddedDriver) {
			log.Error("another program's adapter uses an older Wintun driver; not continuing",
				"adapter", d.String(), "driver_version", d.version, "driver_date", d.date)
			return &OlderDriverError{Adapter: d.String(), Version: d.version}
		}
	}

	release, err := blockDeviceRemoval()
	if err != nil {
		log.Error("could not block device removal for the load; not continuing", "err", err)
		return fmt.Errorf("Lanora could not start its network driver safely (%v) and did not continue, "+
			"because doing so could remove another program's virtual adapter (%s).", err, strings.Join(names, ", "))
	}
	log.Info("device listing and removal are blocked in this process for the duration of the load")

	loadErr := withoutAdminRights(load)
	if loadErr != nil {
		// Either the reduced identity could not be set up, or the library
		// did not start under it. Removal is still blocked, which is the
		// safeguard that matters, so load it as the process itself.
		log.Warn("loading the Wintun library with reduced rights did not work; loading it with removal blocked only", "err", loadErr)
		loadErr = load()
	} else {
		log.Info("the Wintun library was loaded with reduced rights")
	}
	if err := release(); err != nil {
		log.Error("could not restore the device functions after the load", "err", err)
		return fmt.Errorf("Lanora could not finish starting its network driver (%v). Restart the Lanora service and try again.", err)
	}
	if loadErr != nil {
		return fmt.Errorf("loading the network driver library: %w", loadErr)
	}

	after, _ := legacyWintunDevices()
	var removed []string
	for id, d := range before {
		if _, ok := after[id]; !ok {
			removed = append(removed, d.String())
		}
	}
	if len(removed) > 0 {
		sort.Strings(removed)
		log.Error("old-style Wintun adapters disappeared during the load", "removed", removed)
		return &LegacyAdapterError{Removed: removed}
	}
	log.Info("the Wintun library is loaded and every old-style Wintun adapter is still present", "adapters", names)
	return nil
}

// blockDeviceRemoval makes the two Windows functions that the Wintun
// library's clean-up depends on fail, in this process only, until the
// returned function is called:
//
//   - SetupDiGetClassDevsExW, with which the clean-up lists the adapters,
//     returns "no list";
//   - SetupDiCallClassInstaller, with which it removes each one, returns
//     failure.
//
// It does so by overwriting the first instructions of each function with
// "return the failure value", the way a debugger places a breakpoint, and
// restores the original instructions afterwards. The library finds these
// functions by name in setupapi.dll at the moment it first calls them, so it
// reaches the same addresses.
//
// It returns an error, having undone everything, unless it has confirmed
// that listing adapters really fails.
func blockDeviceRemoval() (release func() error, err error) {
	if len(stubReturnInvalidHandle) == 0 || len(stubReturnFalse) == 0 {
		return nil, fmt.Errorf("not supported on %s", runtime.GOARCH)
	}
	for _, p := range []*windows.LazyProc{procSetupDiGetClassDevsExW, procSetupDiCallClassInstaller, procSetupDiDestroyDeviceInfoList} {
		if err := p.Find(); err != nil {
			return nil, err
		}
	}
	list := &patch{name: "SetupDiGetClassDevsExW", addr: procSetupDiGetClassDevsExW.Addr()}
	remove := &patch{name: "SetupDiCallClassInstaller", addr: procSetupDiCallClassInstaller.Addr()}

	if err := list.apply(stubReturnInvalidHandle); err != nil {
		return nil, err
	}
	if err := remove.apply(stubReturnFalse); err != nil {
		return nil, errors.Join(err, list.restore())
	}
	// Ask for the list exactly as the library's clean-up does.
	if h := listRootNetDevices(); h != invalidHandle {
		procSetupDiDestroyDeviceInfoList.Call(h)
		return nil, errors.Join(errors.New("listing network adapters still works after it was blocked"), remove.restore(), list.restore())
	}

	// Creating Lanora's own adapter needs both functions to work again;
	// restore confirms the original instructions are back in place.
	return func() error { return errors.Join(remove.restore(), list.restore()) }, nil
}

// listRootNetDevices makes the call the Wintun library's clean-up starts
// with and returns the resulting device list handle, or invalidHandle.
func listRootNetDevices() uintptr {
	enumerator, _ := windows.UTF16PtrFromString(`ROOT\NET`)
	h, _, _ := procSetupDiGetClassDevsExW.Call(
		uintptr(unsafe.Pointer(&netClass)), uintptr(unsafe.Pointer(enumerator)), 0, 0, 0, 0, 0)
	runtime.KeepAlive(enumerator)
	return h
}

// patch replaces the first instructions of a function in this process.
type patch struct {
	name     string
	addr     uintptr
	original []byte
}

func (p *patch) apply(code []byte) error {
	original := make([]byte, len(code))
	if err := readMemory(p.addr, original); err != nil {
		return fmt.Errorf("reading %s: %w", p.name, err)
	}
	if err := writeMemory(p.addr, code); err != nil {
		return fmt.Errorf("blocking %s: %w", p.name, err)
	}
	p.original = original
	return nil
}

func (p *patch) restore() error {
	if p.original == nil {
		return nil
	}
	if err := writeMemory(p.addr, p.original); err != nil {
		return fmt.Errorf("unblocking %s: %w", p.name, err)
	}
	p.original = nil
	return nil
}

func readMemory(addr uintptr, into []byte) error {
	var n uintptr
	if err := windows.ReadProcessMemory(windows.CurrentProcess(), addr, &into[0], uintptr(len(into)), &n); err != nil {
		return err
	}
	if n != uintptr(len(into)) {
		return fmt.Errorf("read %d of %d bytes", n, len(into))
	}
	return nil
}

// writeMemory writes code over instructions of this process and confirms
// the bytes are in place. WriteProcessMemory makes the page writable for the
// duration of the write and restores its protection, as it does for a
// debugger.
func writeMemory(addr uintptr, code []byte) error {
	process := windows.CurrentProcess()
	var n uintptr
	if err := windows.WriteProcessMemory(process, addr, &code[0], uintptr(len(code)), &n); err != nil {
		return err
	}
	if n != uintptr(len(code)) {
		return fmt.Errorf("wrote %d of %d bytes", n, len(code))
	}
	procFlushInstructionCache.Call(uintptr(process), addr, uintptr(len(code)))
	check := make([]byte, len(code))
	if err := readMemory(addr, check); err != nil {
		return err
	}
	if !bytes.Equal(check, code) {
		return errors.New("the bytes written did not stay in place")
	}
	return nil
}

// guardError marks a failure to set up the reduced identity, as opposed to a
// failure of the function run under it.
type guardError struct{ err error }

func (e *guardError) Error() string { return e.err.Error() }

// withoutAdminRights runs fn on the current thread while it impersonates a
// version of the process token that cannot administer the machine.
func withoutAdminRights(fn func() error) error {
	// Impersonation is a property of the operating-system thread, so the
	// goroutine must not move while it is in effect.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var process windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &process); err != nil {
		return &guardError{fmt.Errorf("opening the process token: %w", err)}
	}
	defer process.Close()

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return &guardError{err}
	}
	// A disabled group stays in the token as "deny only": it can no longer
	// grant anything.
	disable := [1]windows.SIDAndAttributes{{Sid: admins}}
	var restricted windows.Token
	r, _, callErr := procCreateRestrictedToken.Call(
		uintptr(process),
		disableMaxPrivilege, // drop every privilege, including the one needed to remove devices
		1, uintptr(unsafe.Pointer(&disable[0])),
		0, 0,
		0, 0,
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r == 0 {
		return &guardError{fmt.Errorf("creating a restricted token: %w", callErr)}
	}
	defer restricted.Close()

	// A thread can only take on an impersonation token; the restricted one
	// is a primary token, so it is duplicated as one.
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(restricted, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		return &guardError{fmt.Errorf("preparing the restricted token: %w", err)}
	}
	defer impersonation.Close()

	if err := windows.SetThreadToken(nil, impersonation); err != nil {
		return &guardError{fmt.Errorf("switching to the restricted token: %w", err)}
	}
	defer func() {
		if err := windows.RevertToSelf(); err != nil {
			// A thread stuck with a reduced identity would make everything
			// after this fail in confusing ways.
			panic("netcfg: cannot return to the process identity: " + err.Error())
		}
	}()
	return fn()
}

// legacyDevice is one old-style Wintun adapter: a device node under ROOT\NET
// whose hardware ID is "Wintun". These are the devices the Wintun library
// would remove.
type legacyDevice struct {
	id          string    // device instance ID, for example ROOT\NET\0001
	name        string    // the name of its network connection, for example "Astrill VPN"
	description string    // for example "Wintun Userspace Tunnel"
	bound       bool      // a driver is installed on it
	version     string    // that driver's version as Windows records it; "" when unreadable
	date        time.Time // that driver's date; zero when unreadable
}

func (d legacyDevice) String() string {
	label := d.description
	if label == "" {
		label = "Wintun adapter"
	}
	if d.name != "" {
		label = fmt.Sprintf("%q, %s", d.name, label)
	}
	if d.version != "" {
		return fmt.Sprintf("%s [%s, driver %s]", label, d.id, d.version)
	}
	return fmt.Sprintf("%s [%s]", label, d.id)
}

// driver returns the version of the driver installed on the device, and
// whether it could be determined.
func (d legacyDevice) driver() (driverVersion, bool) {
	v, ok := parseDriverVersion(d.version)
	if !ok || d.date.IsZero() {
		return driverVersion{}, false
	}
	return driverVersion{date: d.date, version: v}, true
}

// legacyWintunDevices lists the old-style Wintun adapters on the machine by
// device instance ID. It reads the registry and nothing else, so it can run
// before the Wintun library, or anything that talks to the device
// installer, has been touched. complete is false when part of the registry
// could not be read, in which case there may be adapters it did not see.
func legacyWintunDevices() (devices map[string]legacyDevice, complete bool) {
	devices = map[string]legacyDevice{}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, enumRootNet, registry.ENUMERATE_SUB_KEYS)
	if errors.Is(err, registry.ErrNotExist) {
		return devices, true // this machine has no such device nodes at all
	}
	if err != nil {
		return devices, false
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return devices, false
	}
	complete = true
	for _, name := range names {
		dev, err := registry.OpenKey(registry.LOCAL_MACHINE, enumRootNet+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			complete = false
			continue
		}
		ids, _, err := dev.GetStringsValue("HardwareID")
		if err != nil && !errors.Is(err, registry.ErrNotExist) {
			complete = false
		}
		isWintun := false
		for _, id := range ids {
			if strings.EqualFold(id, "Wintun") {
				isWintun = true
			}
		}
		if isWintun {
			d := legacyDevice{id: `ROOT\NET\` + name}
			d.description, _, _ = dev.GetStringValue("FriendlyName")
			if d.description == "" {
				d.description, _, _ = dev.GetStringValue("DeviceDesc")
			}
			// DeviceDesc has the form "@oem12.inf,%wintun.devicedesc%;Wintun Userspace Tunnel".
			if i := strings.LastIndex(d.description, ";"); i >= 0 {
				d.description = d.description[i+1:]
			}
			d.readDriver(dev)
			devices[d.id] = d
		}
		dev.Close()
	}
	return devices, complete
}

// readDriver fills in what Windows recorded about the driver installed on
// the device, and the name of its network connection.
func (d *legacyDevice) readDriver(dev registry.Key) {
	driver, _, err := dev.GetStringValue("Driver") // "{class GUID}\0007"
	if err != nil || driver == "" {
		return
	}
	d.bound = true
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, classKeys+driver, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	d.version, _, _ = k.GetStringValue("DriverVersion")
	if raw, _, err := k.GetBinaryValue("DriverDateData"); err == nil && len(raw) == 8 {
		ft := windows.Filetime{LowDateTime: binary.LittleEndian.Uint32(raw), HighDateTime: binary.LittleEndian.Uint32(raw[4:])}
		d.date = time.Unix(0, ft.Nanoseconds()).UTC()
	} else if s, _, err := k.GetStringValue("DriverDate"); err == nil {
		d.date, _ = parseDriverDate(s)
	}
	if id, _, err := k.GetStringValue("NetCfgInstanceId"); err == nil && id != "" {
		if conn, err := registry.OpenKey(registry.LOCAL_MACHINE, networkConns+id+`\Connection`, registry.QUERY_VALUE); err == nil {
			d.name, _, _ = conn.GetStringValue("Name")
			conn.Close()
		}
	}
}

func sorted(devices map[string]legacyDevice) []legacyDevice {
	out := make([]legacyDevice, 0, len(devices))
	for _, d := range devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func describe(devices map[string]legacyDevice) []string {
	out := make([]string, 0, len(devices))
	for _, d := range sorted(devices) {
		out = append(out, d.String())
	}
	return out
}

// installWintunDLL makes sure the Wintun library sits next to the running
// program and is the exact file this build was made with, and returns its
// path. The program's own directory is the one place the Wintun binding
// loads it from, and it is as trustworthy as the program itself.
func installWintunDLL() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(exe), "wintun.dll")
	want := sha256.Sum256(wintunDLL)
	if existing, err := os.ReadFile(path); err == nil {
		if got := sha256.Sum256(existing); bytes.Equal(got[:], want[:]) {
			return path, nil
		}
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, wintunDLL, 0o644); err != nil {
		return "", fmt.Errorf("Lanora could not write its network driver library to %s: %w", filepath.Dir(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("Lanora could not install its network driver library at %s: %w", path, err)
	}
	return path, nil
}
