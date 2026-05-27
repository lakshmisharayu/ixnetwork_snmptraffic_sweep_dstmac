# SNMP Traffic Destination MAC Sweep with IxNetwork

Automate SNMP vulnerability testing by sweeping the full destination MAC address space using [Keysight IxNetwork](https://www.keysight.com/us/en/products/network-test/protocol-load-test/ixnetwork.html). The script generates raw traffic containing SNMPv2c GET-request PDUs while iterating through configurable MAC address blocks, and optionally monitors a Juniper router for SNMP authentication failures.

## Features

- **Destination MAC sweep** — iterate over the 48-bit MAC address space in configurable blocks (default ~1 billion per block).
- **Custom SNMP payload** — each frame carries a BER-encoded SNMPv2c GET-request (community `public`, OID `sysDescr.0`) inside Ethernet → IPv4 → UDP → Custom.
- **LAG & physical port support** — automatically detects LAGs and vports in an existing IxNetwork session.
- **Juniper router monitoring** — SSH into a router after each block to check `show log info-log` for `AUTH-5-SNMPD_AUTH_FAILURE` entries.
- **Resumable** — use `--start-block` to resume a long sweep from where it left off.
- **Retry logic** — transient IxNetwork `traffic.Apply()` errors are retried with progressive back-off; failed blocks are skipped and marked in the report.
- **HTML report** — generates a styled report with per-block statistics, timing, router details, and SNMP error detection results.
- **Dry-run mode** — preview block boundaries without connecting to IxNetwork.

## Prerequisites

| Component | Version |
|-----------|---------|
| Python | 3.8+ |
| IxNetwork API Server | Running and accessible |
| IxNetwork Chassis | Ports or LAGs already assigned in the session |
| Juniper Router *(optional)* | SSH access for log monitoring |

## Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/snmp_traffic_destmac_sweep_with_ixnetwork.git
cd snmp_traffic_destmac_sweep_with_ixnetwork

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic sweep (existing IxNetwork session)

```bash
python3 ixnetwork_snmp_mac_sweep.py --session-id 1
```

### Sweep a specific MAC range with router monitoring

```bash
python3 ixnetwork_snmp_mac_sweep.py \
    --session-id 1 \
    --start-mac 02:00:00:00:00:00 \
    --end-mac 02:1f:ff:ff:ff:ff \
    --block-size 999999999 \
    --router 10.37.105.154 \
    --router-user root \
    --router-password xxxxx
```

### Resume from a specific block

```bash
python3 ixnetwork_snmp_mac_sweep.py \
    --session-id 1 \
    --start-mac 02:00:00:00:00:00 \
    --end-mac 02:1f:ff:ff:ff:ff \
    --block-size 999999999 \
    --start-block 4 \
    --router 10.37.105.154 \
    --router-user root \
    --router-password xxxxxx
```

### Dry-run (preview blocks without connecting)

```bash
python3 ixnetwork_snmp_mac_sweep.py --dry-run \
    --start-mac 00:00:00:00:00:00 \
    --end-mac ff:ff:ff:ff:ff:ff
```

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `10.37.117.94` | IxNetwork API server IP |
| `--port` | `65263` | REST API port |
| `--session-id` | — | Existing IxNetwork session ID |
| `--session-name` | — | Existing IxNetwork session name |
| `--start-mac` | `00:00:00:00:00:00` | First destination MAC |
| `--end-mac` | `ff:ff:ff:ff:ff:ff` | Last destination MAC (inclusive) |
| `--block-size` | `999,999,999` | MAC addresses per block |
| `--start-block` | `0` | Block index to start from (for resuming) |
| `--tx-port` | Auto (first LAG/vport) | Transmit port or LAG name |
| `--rx-port` | Auto (second LAG/vport) | Receive port or LAG name |
| `--report` | `snmp_mac_sweep_report.html` | HTML report output path |
| `--router` | — | Juniper router IP for log monitoring |
| `--router-user` | `admin` | Router SSH username |
| `--router-password` | `admin` | Router SSH password |
| `--router-port` | `22` | Router SSH port |
| `--dry-run` | — | Preview config without connecting |

## Traffic Stack

```
Ethernet II  →  IPv4  →  UDP (dst 161)  →  Custom (SNMPv2c GET-request)  →  FCS
```

The SNMP payload is a BER-encoded SNMPv2c GET-request PDU:
- **Version**: SNMPv2c (1)
- **Community**: `public`
- **PDU type**: GetRequest (0xA0)
- **OID**: `1.3.6.1.2.1.1.1.0` (sysDescr.0)

## HTML Report

The generated report includes:
- Test configuration summary (MAC range, block size, timing)
- Router connection details and monitored log pattern
- Per-block results table with Tx/Rx frames, loss %, duration
- **Found Errors** column indicating whether `AUTH-5-SNMPD_AUTH_FAILURE` log entries were detected (Yes/No)

## Estimated Run Times

| MAC Range Size | Blocks (at 1B/block) | Estimated Time |
|---------------|----------------------|----------------|
| ~4.3 billion (`xx:xx:ff:ff:ff:ff`) | 5 | ~2 min |
| ~137 billion (`xx:1f:ff:ff:ff:ff`) | 138 | ~1 hour |
| ~550 billion (`xx:7f:ff:ff:ff:ff`) | 550 | ~4 hours |
| Full 48-bit space | 281,475 | ~87 days |

*Based on ~27 seconds per block at 10% line rate, 10-second transmit duration.*

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
