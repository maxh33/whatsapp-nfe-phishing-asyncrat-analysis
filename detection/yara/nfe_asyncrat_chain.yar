/*
   YARA rules for the fake NF-e (Brazilian electronic invoice) phishing chain:
   WSH JScript dropper -> AutoIt loader -> Donut shellcode -> AsyncRAT (ChaCha20 config fork)

   Author : maxh33
   Date   : 2026-10-02
   License: MIT
   Ref    : https://github.com/maxh33/whatsapp-nfe-phishing-asyncrat-analysis
*/

rule NFe_Phishing_JS_Dropper_AutoIt
{
    meta:
        description = "Fake NF-e JScript dropper that writes AutoIt3 + .au3 loader + encrypted shellcode via ADODB.Stream"
        author = "maxh33"
        date = "2026-10-02"
        reference = "https://github.com/maxh33/whatsapp-nfe-phishing-asyncrat-analysis"
        hash = "ee479f0b931765f95731ef57ce60e2b0aab68e40c00794d3f186e34bc7ca8bb6"
        tlp = "CLEAR"

    strings:
        // COM object names hidden with JS unicode escapes
        $esc1 = "\\u0041ctive\\u0058Object" ascii
        $esc2 = "\\u0057Script" ascii
        $esc3 = "\\u0047etObject" ascii
        // Caesar -2 decoder applied to the embedded base64 payloads
        $caesar = "-65-2+26)%26)+65" ascii
        // payload drop primitives
        $drop1 = ".SaveToFile(" ascii
        $drop2 = ".nodeTypedValue" ascii
        $drop3 = ".dataType=" ascii
        // decoys
        $decoy1 = "System Administration Toolkit" ascii
        $decoy2 = "//# sourceURL=toolkit." ascii

    condition:
        filesize > 300KB and filesize < 30MB
        and all of ($drop*)
        and ( 2 of ($esc*) or $caesar )
        and ( $caesar or any of ($decoy*) )
}

rule NFe_Phishing_AutoIt_Shellcode_Injector
{
    meta:
        description = "AutoIt loader: reads XOR key from HKCU, decrypts shellcode, injects into iexpress.exe/werfault.exe (NtAllocate/NtWrite/NtProtect/NtCreateThreadEx)"
        author = "maxh33"
        date = "2026-10-02"
        reference = "https://github.com/maxh33/whatsapp-nfe-phishing-asyncrat-analysis"
        hash = "c1ac8a0f1b5413bcf56964d3e9f8bcc3a15c0a7ac51c46a7f0dc4a6a4ca724d7"
        tlp = "CLEAR"

    strings:
        $hdr = "#NoTrayIcon" ascii
        $timer = "TimerDiff(" ascii
        // RegRead("HKCU...  as ChrW() chains
        $reg = "RegRead(ChrW(72)&ChrW(75)&ChrW(67)&ChrW(85)" ascii
        // DllStructCreate("byte[" ...
        $struct = "DllStructCreate(ChrW(98)&ChrW(121)&ChrW(116)&ChrW(101)&ChrW(91)" ascii
        $xor = "BitXOR(DllStructGetData(" ascii
        // "ntdll.dll" as ChrW() chain
        $ntdll = "ChrW(110)&ChrW(116)&ChrW(100)&ChrW(108)&ChrW(108)&ChrW(46)&ChrW(100)&ChrW(108)&ChrW(108)" ascii

    condition:
        filesize < 200KB and $hdr and $xor and 3 of ($timer, $reg, $struct, $ntdll)
}

rule AsyncRAT_ChaCha20_Config_Variant
{
    meta:
        description = "AsyncRAT 0.5.8 fork with ChaCha20-encrypted config, base64 string layer and fake Windows Update overlay (WINUPDATE_ACTIVE)"
        author = "maxh33"
        date = "2026-10-02"
        reference = "https://github.com/maxh33/whatsapp-nfe-phishing-asyncrat-analysis"
        hash = "f1af1eca83ae34979f95fdd822b349213df9323bda7ab344595820f6afacf518"
        tlp = "CLEAR"

    strings:
        $m1 = "Decrypt_Base64" ascii
        // base64 user strings (UTF-16LE in the #US heap)
        $b1 = "bWFzdGVyS2V5IGNhbiBub3QgYmUgbnVsbCBvciBlbXB0eS4=" wide // masterKey can not be null or empty.
        $b2 = "V0lOVVBEQVRFX0FDVElWRQ==" wide                         // WINUPDATE_ACTIVE
        $b3 = "UGx1Z2luLlBsdWdpbg==" wide                             // Plugin.Plugin
        $b4 = "TXNncGFjaw==" wide                                     // Msgpack
        $b5 = "VHJhYmFsaGFuZG8gbmFzIGF0dWFsaXphw6fDtWVz" wide         // Trabalhando nas atualizações
        // ChaCha20 constants pushed as IL "ldc.i4 <imm32>"
        $c1 = { 20 65 78 70 61 }  // 0x61707865 "expa"
        $c2 = { 20 6E 64 20 33 }  // 0x3320646E "nd 3"
        $c3 = { 20 32 2D 62 79 }  // 0x79622D32 "2-by"
        $c4 = { 20 74 65 20 6B }  // 0x6B206574 "te k"

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB
        and all of ($c*)
        and 3 of ($b*)
        and $m1
}
