# 04. Detection, hunting and incident response

Practical steps for defenders and small businesses: block, hunt, respond and prevent.

[← 03. Capabilities](03-capabilities-fake-windows-update.md) · [Lessons learned →](lessons-learned.md)

---

## Block now

| What | Where |
|---|---|
| `dhdxhdhdhd[.]duckdns[.]org`, `uhdyadasud[.]duckdns[.]org` | DNS filter / firewall |
| `45.149.153[.]144` (TCP 6606, 7707, 8808) | Firewall egress |
| `*.duckdns.org` | Consider blocking the whole dynamic-DNS zone; legitimate business use is rare |

Machine-readable list: [`iocs/iocs.csv`](../iocs/iocs.csv).

## Detection content in this repo

| File | Detects | Validation |
|---|---|---|
| [`detection/yara/nfe_asyncrat_chain.yar`](../detection/yara/nfe_asyncrat_chain.yar) | Stage 1 dropper, stage 2 AutoIt injector, stage 4 AsyncRAT ChaCha20 fork | Each rule matched only its own stage; **0 hits on 30,309 benign files** (Node.js, Python stdlib, `/usr/bin`, `/usr/share`) |
| [`detection/sigma/proc_creation_win_autoit_au3_from_appdata_via_wsh.yml`](../detection/sigma/proc_creation_win_autoit_au3_from_appdata_via_wsh.yml) | `wscript`/`cscript` → AutoIt `.au3` from AppData; `iexpress.exe` with no arguments spawned from AppData | Syntax-checked; not yet run against live telemetry |

The legitimate `AutoIt3.exe` is intentionally **not** flagged. Detect the behavior, not the interpreter.

## Hunt on Windows endpoints

```powershell
# Live C2 connections
netstat -ano | findstr 45.149.153.144

# iexpress.exe running with no visible window is suspicious on its own
Get-Process iexpress, werfault -ErrorAction SilentlyContinue | Select-Object Id, StartTime, Path

# Leftovers (deleted within seconds, so absence proves nothing)
Get-ChildItem "$env:APPDATA\CloudStore" -Force -ErrorAction SilentlyContinue

# Forced browser extensions
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
                 "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
                 "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist" -ErrorAction SilentlyContinue

# Persistence the operator may add later
schtasks /query /fo LIST /v | Select-String -Context 0,10 "At logon"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

Sysmon / EDR pivots: `wscript.exe` writing `.exe` + `.au3` under `%APPDATA%` (Sysmon EID 11), a random value written under `HKCU\...\CurrentVersion\` and deleted seconds later (EID 13/12), a process running from AppData creating `iexpress.exe` suspended and then a remote thread in it (EID 1 + EID 8 `CreateRemoteThread`), and `iexpress.exe` loading `clr.dll` / `mscoree.dll` (EID 7).

## If a machine was infected

1. **Disconnect it** from the network (cable and Wi-Fi). Do not log into anything from it.
2. From a **clean device**, change passwords: banking, email, e-commerce admin, and the password manager master password.
3. Call the banks; ask them to watch or block transfers.
4. **Crypto:** move funds to a new wallet whose seed was generated on a clean device. Assume the old seed is compromised if it was ever typed or displayed on the infected machine.
5. Reinstall Windows. Removing the process is not enough, because the operator can push any plugin.
6. Report the IOCs (see below).

## Prevent the whole class of attack

- **Neutralize Windows Script Host files.** Associate `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.wsh` and `.hta` with Notepad via GPO, or disable WSH: `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0` (DWORD).
- **Show file extensions** in Explorer, so `…_PDF.js` stops looking like a PDF.
- **Mail gateway:** block script attachments and archives that contain them.
- **WhatsApp Web/Desktop on business PCs:** the same rule applies to files received in chats. Treat a "customer" sending you an invoice as a red flag.
- **Training:** a real NF-e arrives as **PDF (DANFE) or XML**, never as `.js`, `.vbs`, `.hta`, `.bat`, `.exe` or a "click to download the invoice" link.

## Where to report

| Destination | What to send |
|---|---|
| [ThreatFox](https://threatfox.abuse.ch/) | Domains, IP:port, malware family |
| [MalwareBazaar](https://bazaar.abuse.ch/) | The sample itself, for researchers (never publish it on GitHub) |
| DuckDNS (via [duckdns.org](https://www.duckdns.org/)) | Abuse report for the two hostnames |
| Hosting provider of the IP | Abuse contact from WHOIS / RDAP |
| [CERT.br](https://www.cert.br/) | `cert@cert.br`, incident report (Brazil) |
