# Arpent

[Français](README.md) · **English**

[![CI](https://github.com/maxb1906/arpent/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/arpent/actions/workflows/ci.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)

A **portable** network audit and documentation tool. A single executable, **no installation and no administrator rights**: run it from a USB stick on a PC plugged into the network, it discovers devices, identifies open ports and services, flags issues and produces an **audit report** to hand over to the client. Run it again a few months later and it highlights **what has changed**.

Built for technicians, freelancers and MSPs working with small businesses.

## ⚠️ Legal notice

Scanning a network without permission is **illegal**, in Belgium and elsewhere. Only use Arpent on networks you own or for which you have the owner's explicit authorisation. The first audit of each site requires a confirmation, timestamped and included in the report.

## Features

- **Device discovery**: ping (when allowed), TCP probes, active ARP requests on Windows (`SendARP`, no Npcap), the OS ARP table; vendor from the embedded IEEE OUI database; names from reverse DNS, NetBIOS, mDNS/Bonjour and UPnP.
- **Rate-limited TCP port scan** (quick ≈ 100 ports, standard ≈ 1400, full 65535) and targeted UDP (DNS, NetBIOS, SNMP, SSDP, mDNS).
- **Service identification**: banners (SSH, FTP, SMTP, POP3, IMAP, Telnet, MySQL, VNC), HTTP (title, server, redirect, favicon), TLS (certificate, expiry, self-signed, version), SMB (SMBv1, signing), SNMP.
- **Device type** guessed from signatures (printer, NAS, camera, router, hypervisor, phone…).
- **Findings** rated Info / Warning / Critical, explained in plain language for the client: Telnet, SMBv1, RDP, HTTP admin without TLS, expired certificates, SNMP `public`, exposed databases, outdated software…
- **Per-site history** and **change detection**: new unknown device, device gone, port opened or closed, version or certificate changed, IP change; a "known / validated" device list and notes.
- **Report**: self-contained HTML (one file, readable offline, printable to PDF), CSV and JSON exports, in **French or English** regardless of the interface language; customisable issuer and logo.
- **Local** web interface (127.0.0.1 only): nothing is exposed on the audited network, nothing is sent to the Internet.

## Getting started

1. Download `arpent_<version>_windows_amd64.zip` from the [Releases](https://github.com/maxb1906/arpent/releases) and unzip it onto a USB stick.
2. **Double-click `arpent.exe`**: a console window opens and your browser shows the interface.
3. Create a site (the client), run an audit, browse the inventory, then generate the report.
4. Close the console window (or click "Quit" in the interface) to stop.

All data lives in the `arpent-data/` folder **next to the executable**: preferences (`config.yaml`) and one folder per site (`sites/<site>/site.db` and `rapports/`). Nothing is written to the registry or `%APPDATA%`.

> **Windows SmartScreen / antivirus**: the executable is not signed yet. Windows may show "Windows protected your PC": click "More info" then "Run anyway". A network scanning tool may also be flagged by some antivirus software; check the hash against the release's `SHA256SUMS` file. Code signing through SignPath Foundation is being prepared: see [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

## Command line

```
arpent                      # web interface (default)
arpent scan --site "Pharmacy X" --range 192.168.1.0/24 --profile standard
arpent report --site "Pharmacy X" --format html --report-lang en
arpent sites | audits --site … | show --site … | annotate --site … --ip … --label … --known
arpent discover | ports | interfaces | arp --active
arpent config --technician "Name" --company "My company" --logo logo.png
arpent help                 # all commands; arpent <command> -h for options
```

Global options: `--lang fr|en` and `--data <folder>` (or the `ARPENT_DATA` variable).

## What Arpent does and does not do

Arpent observes the network **from one computer, without credentials**: it attempts no authenticated login or exploitation, and does not replace a penetration test. Without administrator rights, discovery relies on full TCP connections and OS APIs; MAC addresses are only known on the local subnet.

## Building

Requirements: [Go](https://go.dev/dl/) (version in `go.mod`). No CGO: cross-compiling to Windows works from Linux or macOS.

```sh
make test        # unit tests (with the race detector)
make windows     # dist/arpent-windows-amd64.exe
make build-all   # windows/amd64, linux/amd64, linux/arm64, darwin/arm64
```

Releases are published by GitHub Actions + GoReleaser on every `vX.Y.Z` tag.

## Contributing

- Translations: `assets/i18n/fr.json` and `en.json` (same keys, checked by tests).
- Audit rules: `assets/rules.yaml`; device signatures: `assets/signatures.yaml` — editable without touching the engine.
- Project brief and decisions (in French): [docs/STRUCTURE.md](docs/STRUCTURE.md).

## License

[GPL-3.0](LICENSE). The OUI database comes from the public IEEE registry.
