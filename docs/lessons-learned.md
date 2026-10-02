# Lessons learned

What this incident taught, from the store counter to the CIL disassembler.

[← 04. Detection and response](04-detection-and-response.md) · [README](../README.md)

---

## For businesses

1. **The target is the store's PC, not the phone.** The `.js` was harmless on the Android phone that received it. The real risk is WhatsApp Web/Desktop on the Windows computer that also runs internet banking and the store admin.
2. **Pretexts follow your workflow.** "Duplicated order, the platform asked me to send you the invoice" is written for e-commerce sellers. Expect the next one to be about returns, chargebacks, shipping labels or marketplace disputes.
3. **A real NF-e is a PDF (DANFE) or an XML.** Anything else, double extensions included (`_PDF.js`), gets deleted. Windows hides extensions by default; turning them on is free.
4. **One GPO beats one antivirus.** Opening `.js`/`.vbs`/`.hta` in Notepad, or disabling Windows Script Host, kills this whole delivery class.
5. **Indicators are perishable.** DuckDNS names and VPS IPs rotate within days. Reporting them the same day (ThreatFox, DuckDNS abuse, hosting abuse, CERT.br) protects more people than any later write-up.

## For analysts

1. **Read before running.** Every stage was recovered statically: XOR, Caesar + base64, `ChrW()` chains, repeating XOR, Donut, base64, ChaCha20. The only execution was a Node.js run to prove the dropper dies off Windows.
2. **Filter the noise first.** 60% padding and thousands of junk lines collapsed to ~90 real lines once base64 continuations and Cyrillic/Greek identifiers were filtered out.
3. **Obfuscators cannot rename the framework.** Type and member references (`SslStream`, `X509Certificate2`, `ManagementObjectSearcher`) and P/Invoke imports (`SetWindowDisplayAffinity`, `RtlSetProcessIsCritical`) identified the family and its features despite fully mangled names.
4. **Constants betray crypto.** `expand 32-byte k` plus 16/12/8/7 rotations means ChaCha. The 12-byte nonce from `DateTime.Ticks` explained why ciphertexts shared a prefix.
5. **Split keys, split artifacts.** The shellcode key lived only in the registry and was deleted after use. Collecting the file alone would not have been enough, and the static path (key from the dropper) avoided that problem.
6. **Fileless after seconds.** The drop deletes itself and the RAT lives inside `iexpress.exe`. Hash-based detection of dropped files misses it; behavior (WSH → AutoIt from AppData → suspended `iexpress.exe` + remote thread) does not.
7. **Living off legitimate binaries.** A signed AutoIt3.exe and a signed `iexpress.exe` carried the attack. Do not block the binaries; detect the parent/child and path combinations.
8. **Commodity RAT, custom fraud feature.** The AsyncRAT core is public. The added overlay with `WDA_EXCLUDEFROMCAPTURE` and a keyboard hook is purpose-built for hands-on banking fraud.

## On AI-assisted analysis

The analysis was done with an AI coding assistant (Claude Code) in an isolated Linux container. It sped up the tedious parts: decoders, IL disassembly scripts, YARA testing. Every claim in these docs was then checked against the disassembled code. That check mattered: an early draft listed a `Version` field in the first beacon that the code does not send. Verify, then publish.
