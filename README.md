# sniffnet-agent

> [!WARNING]
> 
> `sniffnet-agent` isn't yet supported by Sniffnet and is still in early development. <br>
> Stay tuned for updates!

[//]: # ([![Stars]&#40;https://img.shields.io/github/stars/GyulyVGC/listeners?logo=github&style=flat&#41;]&#40;https://github.com/GyulyVGC/listeners&#41;)
[//]: # ([![Downloads]&#40;https://img.shields.io/crates/d/listeners.svg&#41;]&#40;https://crates.io/crates/listeners&#41;)
[//]: # ([![Codecov]&#40;https://codecov.io/gh/GyulyVGC/listeners/graph/badge.svg?token=GSDVTT75C2&#41;]&#40;https://codecov.io/gh/GyulyVGC/listeners&#41;)
[//]: # ([![CI]&#40;https://github.com/sniffnet/sniffnet-agent/workflows/rust/badge.svg&#41;]&#40;https://github.com/sniffnet/sniffnet-agent/actions/&#41;)
[//]: # ([![Crates]&#40;https://img.shields.io/crates/v/sniffnet-agent?&logo=rust&#41;]&#40;https://crates.io/crates/sniffnet-agent&#41;)

Lightweight network flows exporter compatible with [Sniffnet](https://github.com/GyulyVGC/sniffnet).


## Overview 

`sniffnet-agent` captures traffic on a network interface, aggregates packets into
flows, and exports them as IPFIX (RFC 7011) records over UDP to a collector.

It lets you observe devices where running Sniffnet itself isn't practical
(headless servers, routers, embedded boxes, firewalls), forwarding their traffic to a
single Sniffnet instance that aggregates and visualizes activity across your
whole network from one place.

Any IPFIX exporter can feed Sniffnet, but `sniffnet-agent` is built for maximum compatibility:
it emits exactly the Information Elements (IEs) Sniffnet needs, allowing to export only the required data at the
expected rate, without having to configure a more complex exporter to do so.

[//]: # (## Install)

[//]: # (```sh)
[//]: # (cargo install sniffnet-agent)
[//]: # (```)

[//]: # (A working `libpcap` &#40;or `Npcap` on Windows&#41; installation is required.)

## Usage

```sh
sniffnet-agent --interface <IFACE> --collector <HOST:PORT>
```

Run with no arguments to be prompted interactively for the interface and collector.

### Options

| Flag                | Description                                   |
|---------------------|-----------------------------------------------|
| `-i`, `--interface` | Network interface to capture on (e.g. `eth0`) |
| `-c`, `--collector` | Collector address as `HOST:PORT`              |
| `-f`, `--filter`    | BPF filter expression applied to the capture  |
| `-o`, `--odid`      | IPFIX Observation Domain ID [default: 0]      |
| `-v`, `--verbose`   | Enable debug logging                          |
