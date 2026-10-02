# 01. Infection chain: JScript dropper → AutoIt loader → Donut shellcode

How a fake customer on WhatsApp delivers a 3.5 MB "invoice" that turns into an in-memory AsyncRAT client, and how each obfuscation layer was peeled off statically.

[← Back to README](../README.md) · Next: [02. AsyncRAT config and ChaCha20](02-asyncrat-config-chacha20.md)

---

## Stage 0: delivery via WhatsApp Business (fake customer complaint)

The file did not come by email. It arrived on the **WhatsApp Business** account of a small Brazilian e-commerce store:

1. A "customer" writes: *"Boa tarde, fiz uma compra com vocês e acabou que veio meus pedidos duplicados, entrei em contato com a plataforma e pediram pra mandar mensagem pra vocês arrumar o erro, junto com a nota fiscal. Paguei por 1 produto e veio 2."* ("I bought from you and my order came duplicated; the platform told me to message you to fix it, together with the invoice. I paid for 1 product and got 2.")
2. The store's greeting auto-reply goes out.
3. Seconds later the "invoice" arrives: `NFE_7482594_0938402947928387421_PDF.js`, shown by WhatsApp as a 3.6 MB **JS** document.

Why this pretext works:

- **It flips the roles.** Sellers are used to issuing invoices, and a customer reporting a mistake *in the seller's favor* lowers suspicion while creating urgency (stock, refund, marketplace reputation).
- **"The platform told me to"** borrows the authority of the marketplace or store platform.
- **It targets the PC, not the phone.** Stores answer WhatsApp through WhatsApp Web/Desktop on the same Windows computer used for banking and the store admin. That is exactly where a `.js` file runs with a double-click. On the phone, the file is inert.

The sender used a Brazilian mobile number (area code 41, Paraná). It is masked in this repository: WhatsApp senders in these campaigns are often hijacked accounts of real people. It was reported to WhatsApp instead (MITRE T1566.003, Spearphishing via Service).

---

## Stage 1: the `.js` dropper (Windows Script Host)

| Property | Value |
|---|---|
| File name | `NFE_7482594_0938402947928387421_PDF.js` |
| Size | 3,587,467 bytes, 4,143 lines |
| SHA-256 | `ee479f0b931765f95731ef57ce60e2b0aab68e40c00794d3f186e34bc7ca8bb6` |
| Runs with | `wscript.exe` (default handler for `.js` on Windows) |

### Social engineering

- The name ends in `_PDF.js`. With extensions hidden (Windows default), it reads like an invoice PDF.
- The first lines are fake: an "Oracle America Inc. System Administration Toolkit" banner with a made-up DigiCert thumbprint, serial and validity, followed by a fake open-source library header (`wretch-runtime.js`). None of it is a real signature; they are plain comments.
- `//# sourceURL=toolkit.9.30.5.bundle.js` renames the script in stack traces.

### Padding and junk code

About 60% of the file is filler:

- 19 huge base64 variables (`var iwyagwlw="" + "..." ...`) that are declared and **never used**. They only inflate the file past AV and sandbox size limits (MITRE T1027.001, Binary Padding).
- Thousands of dead statements with Cyrillic/Greek identifiers (`var d\u0442\u0432\u0430=Math.floor(...)`, `switch(0){...}`, `try{if(false)...}`) to drown the ~90 real lines.

Filtering out the base64 continuation lines and every line that contains a `\u04xx`/`\u03xx` identifier leaves the real logic.

### String obfuscation

COM ProgIDs are XOR-encoded byte arrays, decoded by a one-line helper:

```js
function itiofpec(ff, iu4){ var yn=""; for(var ql=0; ql<ff.length; ql++) yn += String.fromCharCode(ff[ql]^iu4); return yn; }
// itiofpec([213,229,244,239,246,242,...],134)  ->  "Scripting.FileSystemObject"
```

Decoded with key `134`: `Scripting.FileSystemObject`, `WScript.Shell`, `%APPDATA%`, `Msxml2.DOMDocument`, `bin.base64`, `ADODB.Stream`, `MSXML2.DOMDocument.3.0`, the registry path and `REG_SZ`. The globals themselves are hidden with JS unicode escapes: `new \u0041ctive\u0058Object(n)`, `\u0057Script`.

### Payload encoding

Three payloads are stored as long string concatenations. Each is decoded with a **Caesar shift of −2** (letters and digits) and then base64, using `MSXML2.DOMDocument` with `dataType = "bin.base64"` and written with `ADODB.Stream.SaveToFile`:

| Variable(s) | Written to `%APPDATA%\CloudStore\` | Content |
|---|---|---|
| `qlabfr` | `plçda` | 121,813 bytes, XOR-encrypted shellcode |
| `spdtyu` | `zgmnikcw.au3` | 11,744 bytes, AutoIt script |
| `tweipd` + `himnes` + `ypmpwe` | `hukdrtqp.exe` | 980,064 bytes, **legitimate AutoIt3.exe 3.3.18.0** |

### Hand-off

```js
WScript.Shell.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\jrgmncha\\xvmotf",
                       "2690C12E4232FBA705F399AB7D554CBE", "REG_SZ");
WScript.Shell.Run('"%APPDATA%\\CloudStore\\hukdrtqp.exe" "%APPDATA%\\CloudStore\\zgmnikcw.au3"', 0, false);
WScript.Sleep(30000);
```

The XOR key travels through the registry, so the encrypted file and its key never sit in the same artifact. Window style `0` hides the interpreter.

> **Non-Windows platforms.** Executing the file in Node.js v22 (isolated container) stops at the first real statement with `ReferenceError: WScript is not defined`, and no file is created. Android, iOS, macOS and Linux cannot run this chain.

---

## Stage 2: AutoIt loader (`zgmnikcw.au3`)

AutoIt is a legitimate Windows automation language. Dropping the signed interpreter next to a script avoids shipping a custom PE for this stage (MITRE T1059.010). Every string in the script is a `ChrW(n)&ChrW(n)…` chain; replacing those chains gives readable code. Simplified flow:

```autoit
; anti-sandbox: exits if the 5,153 ms sleep was fast-forwarded (< 3,607 ms)
$t = TimerInit() : Sleep(5153) : If TimerDiff($t) < 3607 Then Exit

$key = RegRead("HKCU\...\CurrentVersion\jrgmncha", "xvmotf")   ; then RegDelete()
$enc = FileRead(@AppDataDir & "\CloudStore\plçda")
$sc  = repeating-XOR($enc, Binary("0x" & $key))                 ; 16-byte key

$target = @SystemDir & "\iexpress.exe"   ; fallback: werfault.exe
CreateProcessW($target, flags = CREATE_SUSPENDED | CREATE_NO_WINDOW)
NtAllocateVirtualMemory(RW) -> NtWriteVirtualMemory -> NtProtectVirtualMemory(RX) -> NtCreateThreadEx

FileDelete(plçda) : FileDelete(zgmnikcw.au3)
Run(@ComSpec & ' /c ping -n 3 127.0.0.1 >nul & del /f /q "...\hukdrtqp.exe"', @SW_HIDE)
```

Techniques: time-based sandbox evasion (T1497.003), registry as key storage (T1112), process injection into a signed Windows binary (T1055) using native `Nt*` APIs, hidden window (T1564.003) and self-cleanup (T1070.004). After a few seconds, **nothing from the drop remains on disk**. The RAT lives only inside `iexpress.exe`.

---

## Stage 3: Donut shellcode

XOR-decrypting `plçda` with `2690C12E4232FBA705F399AB7D554CBE` gives a blob that starts with:

```
E8 C0 79 01 00   call +0x179C0        ; jump over the Donut instance
C0 79 01 00 ...  instance length = 0x179C0
```

That is the layout of a [Donut](https://github.com/TheWover/donut) instance: a position-independent loader that carries an encrypted module (Chaskey cipher, CTR mode) and loads it in memory.

`donut-decryptor` (Volexity) parses it statically:

| Field | Value |
|---|---|
| Instance type | `DONUT_INSTANCE_EMBED` |
| Entropy | `DONUT_ENTROPY_DEFAULT` (encrypted) |
| Module type | `DONUT_MODULE_NET_DLL` |
| Compression | none |
| Module | 91,960-byte .NET DLL, assembly name `plçda`, SHA-256 `f1af1eca…f518` |

Donut hosts the CLR inside `iexpress.exe` and loads the DLL reflectively (T1620). The dropper's check for `C:\Windows\Microsoft.NET\Framework64\v4.0.30319` makes sense here: the final stage needs .NET 4.

Next: [02. AsyncRAT config and ChaCha20](02-asyncrat-config-chacha20.md)
