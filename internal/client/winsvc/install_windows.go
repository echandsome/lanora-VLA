package winsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"lanora/internal/version"
)

const (
	firewallRule  = "Lanora"
	uninstallKey  = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Lanora`
	runKey        = `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
	runValue      = "Lanora"
	serviceArg    = "--service"
	lspSystem     = 0x80000000 // LSP_SYSTEM
	stopTimeout   = 30 * time.Second
	toolTimeout   = 30 * time.Second // for netsh, PowerShell and the like
	shortcutLabel = "Lanora"
)

// Install copies this program into Program Files, registers it as a
// service and starts it. It needs administrator rights, and is safe to run
// again: it then updates the installed copy and restarts the service.
func Install() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target := InstalledExe()

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Lanora needs administrator rights to install its service: %w", err)
	}
	defer m.Disconnect()

	// The running service holds the installed program open; stop it before
	// replacing the file.
	existing, err := m.OpenService(ServiceName)
	if err == nil {
		if err := stopService(existing); err != nil {
			existing.Close()
			return fmt.Errorf("the Lanora service could not be stopped for the update: %w", err)
		}
	}

	if err := os.MkdirAll(InstallDir(), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", InstallDir(), err)
	}
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(target)) {
		if err := copyFile(self, target); err != nil {
			return fmt.Errorf("copying Lanora to %s: %w", target, err)
		}
	}

	config := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  DisplayName,
		Description:  Description,
	}
	service := existing
	if service == nil {
		if service, err = m.CreateService(ServiceName, target, config, serviceArg); err != nil {
			return fmt.Errorf("registering the Lanora service: %w", err)
		}
	} else {
		config.BinaryPathName = `"` + target + `" ` + serviceArg
		if err := service.UpdateConfig(config); err != nil {
			service.Close()
			return fmt.Errorf("updating the Lanora service: %w", err)
		}
	}
	defer service.Close()

	// If the service ever crashes, Windows restarts it.
	service.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}, 24*60*60)

	// Before the service first runs: keep third-party socket hooks out of
	// it, and make what was just installed removable whatever happens next.
	excludeFromSocketHooks(target)
	registerUninstaller(target)

	if err := service.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("starting the Lanora service: %w", err)
	}

	// The rest makes Lanora nicer to live with. None of it is worth failing
	// the installation for, and none of it is allowed to hold it up: these
	// are other programs, and each gets a limited time.
	hidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
	hidden("netsh", "advfirewall", "firewall", "add", "rule", "name="+firewallRule,
		"dir=in", "action=allow", "program="+target, "protocol=udp", "profile=any", "enable=yes",
		"description=Lets other members of your Lanora rooms connect to this computer directly.")
	createShortcut(target)
	return nil
}

// Uninstall stops and removes the service and everything Install created.
// Saved settings (the device identity and remembered room) are kept unless
// purge is set, so that reinstalling brings the same virtual addresses back.
func Uninstall(purge bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("Lanora needs administrator rights to remove its service: %w", err)
	}
	defer m.Disconnect()
	var problem error
	if service, err := m.OpenService(ServiceName); err == nil {
		stopErr := stopService(service)
		delErr := service.Delete()
		service.Close()
		// Neither stops the rest of the removal: what can be removed is
		// removed, and the problem is reported at the end.
		if delErr != nil && !errors.Is(delErr, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			problem = fmt.Errorf("the Lanora service could not be removed (%w); the rest of Lanora was", delErr)
		} else if stopErr != nil {
			problem = fmt.Errorf("the Lanora service could not be stopped (%w); it is removed, and will be gone after a restart", stopErr)
		}
	}

	// Lanora windows still open hold the program file and would keep it
	// from being deleted.
	hidden("taskkill", "/F", "/IM", "Lanora.exe", "/FI", fmt.Sprintf("PID ne %d", os.Getpid()))

	hidden("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule)
	registry.DeleteKey(registry.LOCAL_MACHINE, uninstallKey)
	if key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE); err == nil {
		key.DeleteValue(runValue)
		key.Close()
	}
	os.Remove(shortcutPath())
	if purge {
		if data := os.Getenv("ProgramData"); data != "" {
			os.RemoveAll(filepath.Join(data, "Lanora"))
		}
	}

	removeLater(InstallDir())
	return problem
}

// removeLater deletes a directory once nothing in it is in use any more. A
// running program cannot delete its own file, and the uninstaller is
// usually the installed copy itself, still on screen saying that Lanora
// was removed. So the job goes to a command that outlives this process: it
// tries once a second, for up to ten minutes, until the directory is gone.
func removeLater(dir string) {
	if strings.ContainsAny(dir, `"%`) {
		return // cannot be written into a command line safely
	}
	shell := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	script := `for /l %i in (1,1,600) do @if exist "` + dir + `" (rmdir /s /q "` + dir + `" 2>nul & ping -n 2 127.0.0.1 >nul) else exit`
	cmd := exec.Command(shell)
	// Not the directory being removed: Windows will not delete a directory
	// that is some process's current one, and this command would otherwise
	// inherit ours, which is often exactly that.
	cmd.Dir = os.Getenv("SystemRoot")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The command line is given whole: cmd.exe has its own quoting
		// rules, which the usual argument quoting would break. With /s it
		// takes everything between the first and the last quote as written.
		CmdLine:       `cmd.exe /d /s /c "` + script + `"`,
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS,
	}
	cmd.Start()
}

// stopService stops the service and waits until it has. A service that
// does not stop when asked (it may be hung, or stuck part-way through
// starting, when it accepts no requests at all) has its process ended
// instead: an update or a removal must not be at the mercy of the very
// thing it is replacing.
func stopService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	asked := true
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		asked = false
	}
	if asked && waitStopped(s, stopTimeout) {
		return nil
	}
	if status, err = s.Query(); err == nil && status.State != svc.Stopped && status.ProcessId != 0 {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, status.ProcessId); err == nil {
			windows.TerminateProcess(h, 1)
			windows.CloseHandle(h)
		}
	}
	if !waitStopped(s, 10*time.Second) {
		return errors.New("it did not stop, and its process could not be ended")
	}
	return nil
}

// waitStopped waits for the service to reach the stopped state.
func waitStopped(s *mgr.Service, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		status, err := s.Query()
		if err == nil && status.State == svc.Stopped {
			// Give Windows a moment to release the program file.
			time.Sleep(500 * time.Millisecond)
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err == nil {
		return nil
	}
	// The installed program is in use: a Lanora window started from it is
	// still open. Windows will not overwrite a running program but does
	// allow renaming it, so move the old one aside and put the new one in
	// its place. The open window keeps running the old copy until closed.
	aside := fmt.Sprintf("%s.%d.old", dst, time.Now().Unix())
	if err := os.Rename(dst, aside); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("%w (close every Lanora window and try again)", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Rename(aside, dst)
		os.Remove(tmp)
		return err
	}
	// Remove the old copy when Windows next starts, when nothing holds it.
	if p, err := windows.UTF16PtrFromString(aside); err == nil {
		windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
	return nil
}

// hidden runs a system tool without showing a console window. A tool that
// does not finish within toolTimeout is ended: a helper that hangs must not
// leave the installer waiting for ever behind a window nobody can see.
func hidden(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	cmd.WaitDelay = 2 * time.Second
	return cmd.Run()
}

// excludeFromSocketHooks registers the installed program with Winsock as
// one that only accepts layered service providers certified for system
// use. Third-party socket hooks (such as the one Astrill VPN installs) are
// not in that category and are then not loaded into Lanora, whether it
// runs as the service or as the window. Services are exempt anyway; this
// extends the same protection to every way the program can be started.
func excludeFromSocketHooks(path string) {
	p, err := windows.UTF16FromString(path)
	if err != nil {
		return
	}
	var previous uint32
	var errno int32
	proc := windows.NewLazySystemDLL("ws2_32.dll").NewProc("WSCSetApplicationCategory")
	if proc.Find() != nil {
		return
	}
	proc.Call(
		uintptr(unsafe.Pointer(&p[0])), uintptr(len(p)-1), // length without the terminator
		0, 0, // any command line
		lspSystem,
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&errno)),
	)
}

// registerUninstaller lists Lanora under "Installed apps" in Windows
// Settings.
func registerUninstaller(target string) {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, uninstallKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer key.Close()
	key.SetStringValue("DisplayName", "Lanora")
	key.SetStringValue("DisplayVersion", version.Version)
	key.SetStringValue("Publisher", version.Publisher)
	key.SetStringValue("InstallLocation", InstallDir())
	key.SetStringValue("DisplayIcon", target)
	key.SetStringValue("UninstallString", `"`+target+`" --uninstall`)
	key.SetDWordValue("NoModify", 1)
	key.SetDWordValue("NoRepair", 1)
	if info, err := os.Stat(target); err == nil {
		key.SetDWordValue("EstimatedSize", uint32(info.Size()/1024))
	}
}

func shortcutPath() string {
	data := os.Getenv("ProgramData")
	if data == "" {
		data = `C:\ProgramData`
	}
	return filepath.Join(data, `Microsoft\Windows\Start Menu\Programs`, shortcutLabel+".lnk")
}

// createShortcut adds Lanora to the Start menu for all users.
func createShortcut(target string) {
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	script := "$s = (New-Object -ComObject WScript.Shell).CreateShortcut(" + quote(shortcutPath()) + "); " +
		"$s.TargetPath = " + quote(target) + "; $s.WorkingDirectory = " + quote(InstallDir()) + "; " +
		"$s.Description = 'Lanora virtual LAN'; $s.Save()"
	hidden("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
}

// StartWithWindows reports whether the window is set to open when the
// current user signs in.
func StartWithWindows() bool {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()
	_, _, err = key.GetStringValue(runValue)
	return err == nil
}

// SetStartWithWindows turns opening the window at sign-in on or off for the
// current user. The window then starts in the notification area.
func SetStartWithWindows(on bool) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if !on {
		if err := key.DeleteValue(runValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	exe := InstalledExe()
	if _, err := os.Stat(exe); err != nil {
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	return key.SetStringValue(runValue, `"`+exe+`" --tray`)
}

// Elevate runs this program again with administrator rights and the given
// argument, showing the Windows consent prompt. It returns once the prompt
// was answered; ErrDeclined means the user said no.
func Elevate(arg string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(arg)
	err = windows.ShellExecute(0, verb, file, params, nil, windows.SW_HIDE)
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return ErrDeclined
	}
	return err
}

// ErrDeclined is returned by Elevate when the user refused the prompt.
var ErrDeclined = errors.New("administrator approval was declined")

// MessageBox shows a message from a mode of the program that has no window
// of its own (installing, uninstalling).
func MessageBox(title, text string, isError bool) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION)
	if isError {
		flags = windows.MB_OK | windows.MB_ICONERROR
	}
	windows.MessageBox(0, m, t, flags)
}
