# Security and responsible use

## What this repository contains

- Written analysis, indicators of compromise (IOCs), YARA and Sigma rules.
- A static config extractor that parses an already-extracted .NET client and prints JSON. It never executes code and never writes binaries.

## What it does not contain

- The original sample, the AutoIt loader, the shellcode or the AsyncRAT client, in any form (plain, encoded, zipped or password-protected).
- Full deobfuscated loader source. The docs show excerpts and pseudocode only.
- Personal data of the targeted business, its staff or the sender.

## Getting the sample for research

Look up the SHA-256 values from [`iocs/iocs.csv`](iocs/iocs.csv) on research platforms such as [MalwareBazaar](https://bazaar.abuse.ch/) or VirusTotal. Do not request or post samples in issues or pull requests here.

## Handling the indicators

- Domains and IPs reflect what was observed on 2026-10-01. Dynamic-DNS names and VPS addresses get reassigned; validate before blocking in production.
- Do not connect to, scan or "hack back" the listed infrastructure. Report it instead (see [docs/04](docs/04-detection-and-response.md#where-to-report)).

## Reporting a problem

Found a false positive in a rule, a wrong indicator, or sensitive data that should not be here? Open an issue, or for sensitive matters contact the author through [maxhaider.dev](https://maxhaider.dev).
