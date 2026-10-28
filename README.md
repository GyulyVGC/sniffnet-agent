# sniffnet-agent

[![Stars](https://img.shields.io/github/stars/GyulyVGC/sniffnet-agent?logo=github&style=flat)](https://github.com/GyulyVGC/sniffnet-agent)
[![CI](https://github.com/GyulyVGC/sniffnet-agent/actions/workflows/rust.yml/badge.svg)](https://github.com/GyulyVGC/sniffnet-agent/actions/workflows/rust.yml)
[![Crates](https://img.shields.io/crates/v/sniffnet-agent?&logo=rust)](https://crates.io/crates/sniffnet-agent)

Lightweight network flows exporter compatible with [Sniffnet](https://github.com/GyulyVGC/sniffnet).


## Overview 

`sniffnet-agent` captures traffic on a network interface, aggregates packets into
flows, and exports them as IPFIX (RFC 7011) records over UDP to a collector.

It lets you observe devices where running Sniffnet itself isn't practical
(headless servers, routers, embedded boxes, firewalls), forwarding their traffic to a
single Sniffnet instance that aggregates and visualizes activity across your
whole network from one place.

Any IPFIX exporter can feed Sniffnet, but `sniffnet-agent` is built for maximum compatibility:
it emits exactly the Information Elements (IEs) Sniffnet needs, exporting only the required data at the
expected rate, without having to configure a more complex exporter to do so.

## Installation

> [!NOTE]
>
> A working `libpcap` (or `Npcap` on Windows) installation is required.

<table>
  <tr>
    <td>
      <picture><img alt="Windows" title="Windows" height="85px" src="https://raw.githubusercontent.com/GyulyVGC/sniffnet-agent/main/resources/repository/badges/windows.svg"/></picture>
    </td>
    <td>
      <a href="https://github.com/GyulyVGC/sniffnet-agent/releases/latest/download/sniffnet-agent-windows-x86_64.zip">x86_64</a>
    </td>
  </tr>
  <tr>
    <td>
      <picture><img alt="macOS" title="macOS" height="85px" src="https://raw.githubusercontent.com/GyulyVGC/sniffnet-agent/main/resources/repository/badges/macos.svg"/></picture>
    </td>
    <td>
      <a href="https://github.com/GyulyVGC/sniffnet-agent/releases/latest/download/sniffnet-agent-macos-aarch64.tar.gz">Apple silicon</a> | <a href="https://github.com/GyulyVGC/sniffnet-agent/releases/latest/download/sniffnet-agent-macos-x86_64.tar.gz">Intel</a>
    </td>
  </tr>
  <tr>
    <td>
      <picture><img alt="Linux" title="Linux" height="85px" src="https://raw.githubusercontent.com/GyulyVGC/sniffnet-agent/main/resources/repository/badges/linux.svg"/></picture>
    </td>
    <td>
      <a href="https://github.com/GyulyVGC/sniffnet-agent/releases/latest/download/sniffnet-agent-linux-x86_64.tar.gz">x86_64</a> | <a href="https://github.com/GyulyVGC/sniffnet-agent/releases/latest/download/sniffnet-agent-linux-aarch64.tar.gz">ARM64</a>
    </td>
  </tr>
</table>

The links above download the latest prebuilt binaries directly from
[GitHub releases](https://github.com/GyulyVGC/sniffnet-agent/releases).

Alternatively, install `sniffnet-agent` from crates.io:

```sh
cargo install sniffnet-agent
```

Or pull the Docker image from GitHub Container Registry (only works on Linux):

```sh
docker pull ghcr.io/gyulyvgc/sniffnet-agent:latest
```

## Usage

```sh
sniffnet-agent --interface <IFACE> --collector <HOST:PORT>
```

Run with no arguments to be prompted interactively for the interface and collector.

If running via Docker, the container needs access to the host network namespace and packet-capture
capabilities in order to inspect host interfaces:

```sh
docker run --network host \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  ghcr.io/gyulyvgc/sniffnet-agent:latest \
  --interface <IFACE> --collector <HOST:PORT>
```

### Options

| Flag                | Description                                   |
|---------------------|-----------------------------------------------|
| `-i`, `--interface` | Network interface to capture on (e.g. `eth0`) |
| `-c`, `--collector` | Collector address as `HOST:PORT`              |
| `-f`, `--filter`    | BPF filter expression applied to the capture  |
| `-o`, `--odid`      | IPFIX Observation Domain ID [default: 0]      |
| `-v`, `--verbose`   | Enable debug logging                          |
