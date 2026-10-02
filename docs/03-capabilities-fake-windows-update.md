# 03. Capabilities: remote control, plugins and the fake Windows Update screen

What the client can do once connected, with emphasis on the overlay that hides banking fraud from the victim.

[← 02. AsyncRAT config](02-asyncrat-config-chacha20.md) · Next: [04. Detection and response](04-detection-and-response.md)

---

## Startup sequence

1. Registers an `AssemblyResolve` handler (used to load plugins from memory) and forces TLS 1.2.
2. Checks the .NET 4.8 `Release` value under `HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full`. If it is missing, it downloads `ndp48-x86-x64-allos-enu.exe` from Microsoft (`go.microsoft.com/fwlink/?linkid=2088631`) and installs it silently (`/q /norestart`).
3. Waits `Delay` seconds, decrypts the settings and verifies the server signature.
4. Creates the mutex `HquPKsyB1gUp` (single instance).
5. Optional modules, all driven by config flags and **disabled in this sample**: anti-analysis, persistence, browser-extension push.
6. Picks a random host and a random port from the config, connects over TLS, pins the server certificate and starts the command loop.

## First beacon

Sent as a MessagePack map of type `ci`: `HWID`, `User`, `OS` (full name + 32/64-bit), `Path`, `Admin` (Admin/User), `Performance` (active window title via `GetForegroundWindow`/`GetWindowText`), `Pb` (Pastebin), `Antivirus` (WMI `root\SecurityCenter2` → `Select * from AntivirusProduct`), `Installed` (the executable's last-write time, UTC), `Pong` and `Grp` (group).

## Commands handled by the core client

| Command | Purpose |
|---|---|
| `wu` (`Option: on/off`, `Lang`) | Show or hide the fake Windows Update overlay |
| `hbr` | Heartbeat / ping reply |
| `sp` + `Dll` hash | Server offers a plugin; the client replies whether it already has it cached |
| `sv` + `Dll` bytes | Receive a plugin, cache it under `HKCU\Software\<HWID>` and run `Plugin.Plugin.Run(...)` |

Everything else (remote desktop, keylogger, browser password and cookie stealing, file manager, process manager, shell) arrives as **plugins** (MITRE T1105). The core stays small and gains features on demand from the operator.

## The fake Windows Update overlay

A borderless, topmost, full-screen form with a spinner and a percentage, in **42 languages**. Portuguese (Brazil) comes first in the table, which matches the NF-e lure:

> **Trabalhando nas atualizações** · *n*% concluído
> Não desligue o computador. Isso pode demorar um pouco.
> O PC será reiniciado várias vezes.

What makes it a fraud tool rather than a prank:

| API | Argument | Effect |
|---|---|---|
| `SetWindowDisplayAffinity` | `0x11` `WDA_EXCLUDEFROMCAPTURE` (fallback `WDA_MONITOR`) | The overlay is **invisible to screen capture**. The operator's remote-desktop plugin sees the real desktop; the victim only sees "updating". |
| `SetWindowsHookEx` | `13` `WH_KEYBOARD_LL` | Swallows keyboard input, so the victim cannot Alt+Tab, Ctrl+Esc or type. |
| `SetSystemCursor` / `SystemParametersInfo(SPI_SETCURSORS)` | n/a | Hides the mouse cursor, restores it afterwards. |
| `SetThreadExecutionState` | `0x80000003` | Keeps the display and system awake during the session. |

This is the playbook of Brazilian banking fraud: the operator logs into the victim's internet banking or crypto wallet through the victim's own machine (same IP, same device fingerprint, already-trusted browser), while the victim waits for an "update" to finish.

## Other features present in the code

- **Browser extension push.** Writes `pkeenpghpkeocnndbeclgeojlbnoebcd;https://clients2.google.com/service/update2/crx` into `ExtensionInstallForcelist` for Chrome, Edge and Brave (HKLM, needs admin). Disabled in this sample.
- **Persistence.** As admin: `schtasks /create /f /sc onlogon /rl highest`. Otherwise: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (the path is stored reversed). Then a `.bat` relaunches the copy and deletes the original. Disabled in this sample.
- **Critical process.** `RtlSetProcessIsCritical(1)` makes Windows blue-screen if the process is killed (BSOD flag, disabled here).
- **Anti-debug.** `CheckRemoteDebuggerPresent`.

Next: [04. Detection and response](04-detection-and-response.md)
