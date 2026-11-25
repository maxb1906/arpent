# Arpent

[Français](README.md) · **English**

[![CI](https://github.com/maxb1906/arpent/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/arpent/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A **portable** network audit and documentation tool. A single executable, no installation and no administrator rights: run it from a USB stick on a PC plugged into the network, it discovers devices, identifies open ports and services, then produces a visual inventory and an audit report to hand over to the client. Run it again a few months later and it highlights what has changed.

> **Status: under development (step 0 — foundation).** Nothing is usable for auditing a network yet. The full project brief (in French) is in [docs/STRUCTURE.md](docs/STRUCTURE.md).

## ⚠️ Legal notice

Scanning a network without permission is **illegal**, in Belgium and elsewhere. Only use Arpent on networks you own or for which you have the owner's explicit authorisation.

## Planned features

- Discovery of devices on the subnet (OS ARP table, `SendARP` on Windows, reverse DNS, NetBIOS, mDNS, SSDP) and vendor lookup via the OUI database.
- Rate-limited TCP connect scan, quick / standard / full profiles.
- Service and banner identification (HTTP, TLS, SSH, SMB, SNMP…).
- Findings (Telnet, SMBv1, expired certificates, exposed databases…).
- Per-site history and change detection between two audits.
- Self-contained HTML report, PDF, CSV/JSON exports — in French or English.

## Usage

**Double-click `arpent.exe`**: Arpent starts a local interface on `127.0.0.1` and opens your browser. Create a site (the client), run an audit, browse the inventory. Data is stored in `arpent-data/`, next to the executable: everything stays on the USB stick. Close the black window to quit.

From the command line:

```
arpent scan --site "Pharmacy X" --range 192.168.1.0/24 --profile standard --technician "Name"
arpent sites | arpent audits --site "Pharmacy X" | arpent show --site "Pharmacy X"
arpent discover | arpent ports | arpent interfaces | arpent arp --active
arpent help
```

Global options: `--lang fr|en` (otherwise the system language) and `--data <folder>` (otherwise `arpent-data/` next to the exe, or the `ARPENT_DATA` variable).

## Building

Requirements: [Go](https://go.dev/dl/) (version given in `go.mod`). No CGO.

```sh
make test        # unit tests
make build       # binary for the current machine → dist/arpent
make windows     # dist/arpent-windows-amd64.exe
make build-all   # windows/amd64, linux/amd64, linux/arm64, darwin/arm64
```

## Translations

All user-facing text lives in `assets/i18n/fr.json` and `assets/i18n/en.json`, embedded in the executable. To add a string: add the same key to both files (a test checks they stay in sync), then call `tr.T("my.key", "variable", value)` in the code.

## License

[GPL-3.0](LICENSE).
