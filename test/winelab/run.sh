#!/usr/bin/env bash
# Runs inside the lanora-winelab container (see lab.sh): the Windows builds
# of Lanora under Wine, one scenario at a time.
set -uo pipefail

NETCLASS='{4d36e972-e325-11ce-bfc1-08002be10318}'
ADAPTER='ROOT\NET\0000'
DEV="HKLM\\System\\CurrentControlSet\\Enum\\$ADAPTER"
DRV="HKLM\\System\\CurrentControlSet\\Control\\Class\\$NETCLASS\\0000"
SVC='HKLM\System\CurrentControlSet\Services\Lanora'
UNINSTALL='HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\Lanora'
C=/wine/drive_c
LAB=$C/lanora-lab
SRV=http://127.0.0.1:18490
ADMIN_PW=winelab-admin-pw
ROOM_PW=correct-horse-battery
# The official Wintun 0.14.1 library for amd64.
WINTUN_SHA256=e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
LOG=/tmp/scenario.log
PASSED=() FAILED=()

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
say()   { printf '      %s\n' "$*"; }
reg()   { wine reg "$@" 2>/dev/null | tr -d '\r'; }

# plant <driver version> <driver date>: put an old-style Wintun adapter in
# the registry, as OpenVPN's tapctl leaves one behind for Astrill VPN.
plant() {
    reg add "$DEV" /v HardwareID /t REG_MULTI_SZ /d Wintun /f >/dev/null
    reg add "$DEV" /v ClassGUID /t REG_SZ /d "$NETCLASS" /f >/dev/null
    reg add "$DEV" /v Class /t REG_SZ /d Net /f >/dev/null
    reg add "$DEV" /v FriendlyName /t REG_SZ /d "Lanora lab adapter" /f >/dev/null
    reg add "$DEV" /v Service /t REG_SZ /d wintun /f >/dev/null
    reg add "$DEV" /v Driver /t REG_SZ /d "$NETCLASS\\0000" /f >/dev/null
    reg add "$DRV" /v DriverVersion /t REG_SZ /d "$1" /f >/dev/null
    reg add "$DRV" /v DriverDate /t REG_SZ /d "$2" /f >/dev/null
}
unplant() { reg delete "$DEV" /f >/dev/null; reg delete "$DRV" /f >/dev/null; }
adapter_present() { wine reg query "$DEV" /v HardwareID >/dev/null 2>&1; }

# gotest <test program> <test name> [VAR=value ...]: run one Go test in a
# fresh process. Succeeds only if the test ran and passed (not if skipped).
gotest() {
    local bin=$1 name=$2; shift 2
    (cd "$LAB" && env "$@" timeout 120 wine "$bin" -test.run "^$name\$" -test.v) >"$LOG" 2>&1
    grep -q -- "--- PASS: $name" "$LOG"
}
show() { grep -v -e '^=== RUN' -e '^PASS$' -e '^ok ' "$LOG" | sed 's/^/      | /' | cut -c1-260; }
has()  { grep -q -F -- "$1" "$LOG" || { say "missing from the output: $1"; return 1; }; }

run() {
    echo "== $1"
    if "$1"; then
        [ -z "${VERBOSE:-}" ] || show
        green "   PASS $1"; PASSED+=("$1")
    else
        red "   FAIL $1"; show; FAILED+=("$1")
    fi
}

# --- scenarios ---------------------------------------------------------------

# The two Windows functions the Wintun library's clean-up needs can be made
# to fail in this process, and put back.
device_functions_can_be_blocked() {
    unplant
    gotest netcfg.test.exe TestBlockDeviceRemoval
}

# The control: loading the library the ordinary way deletes the adapter.
# This is what a program using Wintun does to Astrill.
ordinary_load_removes_adapter() {
    plant 0.14.0.0 10-13-2021
    gotest netcfg.test.exe TestUnguardedLoadRemovesLegacyAdapters "LANORA_TEST_DESTROY_LEGACY_ADAPTER=$ADAPTER" || return 1
    if adapter_present; then say "the adapter is still in the registry"; return 1; fi
    say "the adapter is gone from the registry after an ordinary load"
}

# Either of the two blocks is enough by itself.
removal_block_alone_keeps_adapter() {
    plant 0.14.0.0 10-13-2021
    gotest netcfg.test.exe TestRemovalBlockAloneKeepsLegacyAdapters "LANORA_TEST_DESTROY_LEGACY_ADAPTER=$ADAPTER" || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
}

# The way Lanora loads the library: it ends up loaded, the adapter stays.
lanora_load_keeps_adapter() {
    plant 0.14.0.0 10-13-2021
    gotest netcfg.test.exe TestGuardedLoadKeepsLegacyAdapters "LANORA_TEST_LEGACY_ADAPTER=$ADAPTER" || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
    say "the library is loaded and the adapter is still in the registry"
}

# An adapter on an older driver: Lanora stops before loading anything.
older_driver_is_refused() {
    plant 0.8.1.0 4-6-2020
    gotest netcfg.test.exe TestOlderDriverIsRefused "LANORA_TEST_OLD_DRIVER_ADAPTER=$ADAPTER" || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
}

# The access rules of the service's pipe are ones the system accepts.
pipe_rules_are_valid() {
    gotest ipc.test.exe TestPipeSecurityDescriptor
}

# "lanora-cli doctor": passes with a current adapter present, fails with an
# old one, reaches the server, and touches nothing.
doctor_reports() {
    # In a directory of its own, to see that it leaves nothing behind.
    local dir=$C/lanora-doctor
    rm -rf "$dir" && mkdir -p "$dir" && cp /in/lanora-cli.exe "$dir/"
    plant 0.14.0.0 10-13-2021
    (cd "$dir" && timeout 120 wine lanora-cli.exe doctor -server $SRV) >"$LOG" 2>&1
    local rc=$?
    [ $rc -eq 0 ] || { say "exit code $rc with a current adapter"; return 1; }
    has "[ ok ] Other programs' Wintun adapters" && has "Lanora lab adapter" &&
        has "[ ok ] Wintun driver version" && has "[ ok ] Protection of other programs' adapters" &&
        has "[ ok ] Server" && has "All checks passed." || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
    [ "$(ls "$dir")" = lanora-cli.exe ] || { say "doctor left files behind: $(ls "$dir" | tr '\n' ' ')"; return 1; }

    plant 0.8.1.0 4-6-2020
    (cd "$dir" && timeout 120 wine lanora-cli.exe doctor) >"$LOG" 2>&1
    rc=$?
    [ $rc -eq 1 ] || { say "exit code $rc with an old adapter, want 1"; return 1; }
    has "[FAIL] Wintun driver version" || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
}

# The real client: joins the room on a real server, loads the library with
# the safeguards, and then reports cleanly that the adapter cannot be made
# (Wine has no network drivers). The planted adapter survives all of it.
client_joins_and_stops_at_the_adapter() {
    plant 0.14.0.0 10-13-2021
    (cd "$LAB" && LANORA_PASSWORD=$ROOM_PW timeout 120 wine lanora-cli.exe up -v -server $SRV -room "$ROOM" -nickname winelab) >"$LOG" 2>&1
    local rc=$?
    [ $rc -eq 1 ] || { say "exit code $rc, want 1"; return 1; }
    has "Setting up the network adapter" && has "old-style Wintun adapters are present" &&
        has "every old-style Wintun adapter is still present" &&
        has "Lanora could not create its network adapter" || return 1
    adapter_present || { say "the adapter is gone from the registry"; return 1; }
    echo "$WINTUN_SHA256  $LAB/wintun.dll" | sha256sum -c --status || { say "wintun.dll next to the program is not the official file"; return 1; }
    say "joined, loaded the library safely, stopped at: $(grep -F 'could not create' "$LOG" | tail -1 | cut -c1-150)"
}

# Installing: the program is copied to Program Files, the service is
# registered to start with Windows under the right name, account and
# argument, and Lanora appears in "Installed apps" with a way to remove it.
# (Whether the service then starts is not checked: Wine's own service
# manager starts services unreliably, and Wine cannot create the pipe the
# service listens on, so it could not stay up in any case.)
install_registers_service() {
    unplant
    mkdir -p $C/dl && cp /in/Lanora.exe $C/dl/
    # The installer may then wait a long time on Wine's service manager;
    # it is given 25 seconds in all.
    (cd $C/dl && timeout 25 wine Lanora.exe --install >/dev/null 2>&1 &)
    for _ in $(seq 25); do wine reg query "$UNINSTALL" /v UninstallString >/dev/null 2>&1 && break; sleep 1; done
    for _ in $(seq 30); do pgrep -f 'Lanora.exe --install' >/dev/null || break; sleep 1; done
    reg query "$SVC" >"$LOG" 2>&1; reg query "$UNINSTALL" >>"$LOG" 2>&1
    has '"C:\Program Files\Lanora\Lanora.exe" --service' && has "LocalSystem" && has "Lanora Virtual LAN" &&
        has '"C:\Program Files\Lanora\Lanora.exe" --uninstall' || return 1
    grep -E '^\s+Start\s+REG_DWORD\s+0x2$' "$LOG" >/dev/null || { say "the service is not set to start automatically"; return 1; }
    cmp -s /in/Lanora.exe "$C/Program Files/Lanora/Lanora.exe" || { say "the program in Program Files is not a copy of the installer"; return 1; }
}

# Uninstalling: the service, the program and the "Installed apps" entry go,
# even though the uninstaller is the installed program itself and is still
# on screen saying so.
uninstall_removes_everything() {
    [ -s "$C/Program Files/Lanora/Lanora.exe" ] || { say "not installed (run install_registers_service first)"; return 1; }
    (cd "$C/Program Files/Lanora" && timeout 100 wine Lanora.exe --uninstall >/dev/null 2>&1 &)
    for _ in $(seq 80); do
        if ! wine reg query "$SVC" >/dev/null 2>&1 && [ ! -e "$C/Program Files/Lanora" ]; then break; fi
        # The uninstaller ends by saying "Lanora was removed" and waits for
        # OK; the program's own file can only go once that is answered.
        for w in $(xdotool search --name '^Lanora$' 2>/dev/null); do xdotool key --window "$w" Return 2>/dev/null; done
        sleep 1
    done
    : >"$LOG"
    if wine reg query "$SVC" >/dev/null 2>&1; then say "the service is still registered"; return 1; fi
    if wine reg query "$UNINSTALL" >/dev/null 2>&1; then say "the Installed apps entry is still there"; return 1; fi
    if [ -e "$C/Program Files/Lanora" ]; then
        say "the program folder is still there: $(ls "$C/Program Files/Lanora" | tr '\n' ' ')"
        say "processes: $(ps -eo args | grep -i -E '[L]anora|[c]md\.exe|[p]ing' | cut -c1-110 | tr '\n' ';')"
        say "install.log: $(cat "$C/ProgramData/Lanora/install.log" 2>/dev/null | tail -2 | tr '\n' ' ')"
        return 1
    fi
}

ALL=(device_functions_can_be_blocked ordinary_load_removes_adapter removal_block_alone_keeps_adapter
     lanora_load_keeps_adapter older_driver_is_refused pipe_rules_are_valid doctor_reports
     client_joins_and_stops_at_the_adapter install_registers_service uninstall_removes_everything)

# --- set-up ------------------------------------------------------------------

Xvfb :99 -screen 0 800x600x24 -nolisten tcp >/dev/null 2>&1 &
sleep 1
echo "starting Wine ($(wine --version))…"
wineboot --init >/dev/null 2>&1
# wineboot returns before Wine's own services are all up; a service started
# in that moment can be left waiting.
for _ in $(seq 30); do reg query 'HKLM\System\CurrentControlSet\Services\PlugPlay' >/dev/null 2>&1 && wine sc query PlugPlay 2>/dev/null | grep -q RUNNING && break; sleep 1; done
sleep 3
mkdir -p "$LAB" && cp /in/netcfg.test.exe /in/ipc.test.exe /in/lanora-cli.exe "$LAB/"

LANORA_DATA_DIR=/tmp/srv LANORA_LISTEN=127.0.0.1:18490 LANORA_RELAY_LISTEN=127.0.0.1:18490 LANORA_TLS=off \
    LANORA_ADMIN_PASSWORD=$ADMIN_PW LANORA_LOG_LEVEL=warn /in/lanora-server >/tmp/server.log 2>&1 &
for _ in $(seq 50); do curl -s -o /dev/null $SRV/healthz && break; sleep 0.2; done
curl -s -c /tmp/jar -o /dev/null $SRV/api/admin/login -H 'Content-Type: application/json' \
    -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}"
ROOM=$(curl -s -b /tmp/jar $SRV/api/admin/rooms -H 'Content-Type: application/json' \
    -d "{\"name\":\"wine lab\",\"capacity\":8,\"password\":\"$ROOM_PW\"}" | jq -r .room.public_id)
[ -n "$ROOM" ] && [ "$ROOM" != null ] || { red "could not create a room on the lab server"; cat /tmp/server.log; exit 1; }

for s in "${@:-${ALL[@]}}"; do
    if declare -F "$s" >/dev/null; then run "$s"; else red "unknown scenario: $s"; FAILED+=("$s"); fi
done

echo
green "   passed: ${#PASSED[@]}  ${PASSED[*]:-}"
if [ ${#FAILED[@]} -gt 0 ]; then red "   failed: ${#FAILED[@]}  ${FAILED[*]}"; exit 1; fi
