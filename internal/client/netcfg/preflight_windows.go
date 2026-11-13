package netcfg

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// Preflight checks what Lanora depends on in order to run next to another
// VPN on this computer, before anything is risked on it. It does not load
// the Wintun library and does not create an adapter, so it cannot disturb
// another program's adapter whatever it finds; the one thing it changes,
// blocking two device functions inside this process, it undoes before
// returning.
//
// Run it first on a computer that has Astrill VPN installed
// ("lanora-cli doctor"). If every check passes, joining a room takes the
// same steps for real.
func Preflight() []Check {
	var out []Check
	add := func(name string, ok bool, detail string) {
		out = append(out, Check{Name: name, OK: ok, Detail: detail})
	}

	if isAdministrator() {
		add("Administrator rights", true, "This program is running as an administrator, as creating a network adapter requires.")
	} else {
		add("Administrator rights", false, "This program is not running as an administrator. Start it from an "+
			"administrator prompt; the checks below are still valid, but joining a room from here would fail.")
	}

	devices, complete := legacyWintunDevices()
	switch {
	case !complete:
		add("Other programs' Wintun adapters", false, "Part of the device registry could not be read, so there may be "+
			"adapters that were not seen. Found: "+orNone(describe(devices))+".")
	case len(devices) == 0:
		add("Other programs' Wintun adapters", true, "None. No other program on this computer has the kind of "+
			"adapter that the Wintun library removes (Astrill VPN's is of that kind), so there is nothing to protect.")
	default:
		add("Other programs' Wintun adapters", true, "Found "+strings.Join(describe(devices), "; ")+
			". Lanora will load its driver library without letting it remove "+plural(len(devices), "this adapter", "these adapters")+".")
	}

	older := ""
	for _, d := range sorted(devices) {
		if v, known := d.driver(); d.bound && (!known || v.olderThan(embeddedDriver)) {
			older = d.String()
		}
	}
	switch {
	case older != "":
		add("Wintun driver version", false, fmt.Sprintf("%s runs an older Wintun driver than Lanora's (%s), or one that "+
			"could not be identified. Lanora would have to replace it, and will refuse to connect instead. Update the "+
			"program that adapter belongs to.", older, embeddedDriver))
	case len(devices) > 0:
		add("Wintun driver version", true, fmt.Sprintf("Every such adapter runs Wintun driver %s or newer, the version "+
			"Lanora uses. Nothing will be replaced.", embeddedDriver))
	default:
		add("Wintun driver version", true, fmt.Sprintf("Lanora uses Wintun driver %s. If an older one is installed, "+
			"the Wintun library updates it, as it does for every program that uses it.", embeddedDriver))
	}

	release, err := blockDeviceRemoval()
	if err == nil {
		err = release()
	}
	if err != nil {
		add("Protection of other programs' adapters", false, "The functions the Wintun library would use to remove "+
			"another program's adapter could not be blocked and unblocked in this process ("+err.Error()+"). Lanora "+
			"will refuse to connect on a computer that has such adapters.")
	} else {
		add("Protection of other programs' adapters", true, "The functions the Wintun library would use to remove "+
			"another program's adapter were blocked, confirmed to fail, and restored.")
	}

	if err := withoutAdminRights(func() error { return nil }); err != nil {
		add("Loading with reduced rights", true, "Not available here ("+err.Error()+"). This is the second of two "+
			"safeguards; the first is enough.")
	} else {
		add("Loading with reduced rights", true, "Available: the driver library can be loaded on a thread that has "+
			"given up its administrator rights.")
	}
	return out
}

// isAdministrator reports whether this program may administer the
// computer: the Administrators group is in its token and in force. For an
// administrator's ordinary, unelevated programs the group is present but
// switched off, and this is false.
func isAdministrator() bool {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := windows.Token(0).IsMember(admins)
	return err == nil && member
}

func orNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
