# 02. AsyncRAT config: identifying ChaCha20 from .NET IL

The final .NET client is an AsyncRAT 0.5.8 fork. Stock AsyncRAT protects its settings with AES-256-CBC + HMAC-SHA256 (PBKDF2-derived key). This fork replaced that with **ChaCha20** and a custom key folding. This page shows how that was found without a decompiler, and gives the full decrypted config.

[← 01. Infection chain](01-infection-chain.md) · Next: [03. Capabilities](03-capabilities-fake-windows-update.md)

---

## Tooling without a .NET runtime

The analysis container had no .NET SDK, so everything was done in Python:

- [`dnfile`](https://github.com/malwarefrank/dnfile) to parse metadata tables (TypeDef, MemberRef, ImplMap) and the `#US` user-strings heap.
- [`dncil`](https://github.com/mandiant/dncil) to disassemble every method body to CIL, resolving tokens to names.

Identifiers are obfuscated (`IIlIIlOIIlIl_OIOIOlIIIlI.IlIOIIOIlllI0OI0IIII`), but **references to the framework cannot be renamed**. `SslStream`, `X509Certificate2`, `RSACryptoServiceProvider.VerifyHash`, `ManagementObjectSearcher`, `Mutex`, `GZipStream` and a `Plugin.Plugin` / `Msgpack` string pair point straight at AsyncRAT.

## Layer 1: base64 on every literal

Every `ldstr` goes through a method literally named `Decrypt_Base64`, which is just `Encoding.UTF8.GetString(Convert.FromBase64String(s))`. Decoding the whole `#US` heap reveals the UI text, registry paths and commands at once. Settings values are still encrypted after this layer.

## Layer 2: spotting ChaCha20 in IL

The class whose constructor throws `"masterKey can not be null or empty."` holds the cipher. Three details give it away:

**1. The block function pushes the ChaCha constants:**

```
ldc.i4 1634760805   // 0x61707865  "expa"
ldc.i4 857760878    // 0x3320646E  "nd 3"
ldc.i4 2036477234   // 0x79622D32  "2-by"
ldc.i4 1797285236   // 0x6B206574  "te k"
```

That is `"expand 32-byte k"`, the ChaCha/Salsa signature. The quarter-round helper rotates by **16, 12, 8, 7** (ChaCha, not Salsa's 7, 9, 13, 18), it runs 10 double rounds (20 rounds total), and words 13–15 are read from a 12-byte nonce (RFC 8439 layout).

**2. Encrypt prepends a 12-byte nonce built from `DateTime.UtcNow.Ticks`:**

```
nonce[i] = (byte)(ticks >> ((i * 4) & 63))   for i in 0..11
output   = nonce || ChaCha20(key, nonce, counter = 1, plaintext)
```

This explains why many ciphertexts share the same first 12 bytes: the builder encrypted them in the same tick window.

**3. Key derivation folds the master key into 32 bytes:**

```python
key = bytearray(32)
for i, b in enumerate(master_key.encode()):
    key[i % 32] ^= b
    key[(i + 7) % 32] = (key[(i + 7) % 32] + b) & 0xFF
```

The master key itself is stored as base64 of base64: `YjJoeU1HTkpj…` → `b2hyMGNJcEoz…` → `ohr0cIpJ3Kqz8OGMMccAyeiCSpknqYA6`.

## Decrypted configuration

Produced by [`tools/asyncrat_chacha_config.py`](../tools/asyncrat_chacha_config.py):

| Setting | Value |
|---|---|
| Ports | `6606, 7707, 8808` (AsyncRAT defaults) |
| Hosts | `127.0.0.1`, `dhdxhdhdhd[.]duckdns[.]org`, `uhdyadasud[.]duckdns[.]org` |
| Version | `0.5.8` |
| Install (persistence) | `false` |
| Install folder | `%AppData%` |
| Master key | `ohr0cIpJ3Kqz8OGMMccAyeiCSpknqYA6` |
| Mutex | `HquPKsyB1gUp` |
| Certificate | X.509, `CN=Server`, notBefore 2026-05-30, SHA-1 `E3C5A7712CE7565835F39C1874F9C4A294F10061` |
| Server signature | RSA signature over the master key, checked with `VerifyHash(SHA256)` before connecting |
| Anti-analysis / anti-process / BSOD / extension push | all `false` |
| Pastebin | `null` |
| Delay | 3 s |
| Group | `Default` |

On 2026-10-01 both DuckDNS hostnames resolved to `45.149.153[.]144`. The certificate check means the client only talks to a server holding the matching private key, so passive sinkholing does not work without it.

## Reproduce

```bash
pip install -r tools/requirements.txt
python tools/asyncrat_chacha_config.py extracted_client.dll       # auto-finds the key
python tools/asyncrat_chacha_config.py --key <master_key> <b64>   # decrypt single values
```

Next: [03. Capabilities and the fake Windows Update overlay](03-capabilities-fake-windows-update.md)
