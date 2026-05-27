#!/usr/bin/env python3
"""
IxNetwork SNMP Traffic Stream with Destination MAC Sweep.

This script automates SNMP vulnerability testing by generating raw traffic
streams through an IxNetwork chassis while sweeping the destination MAC
address space in configurable blocks. For each block, the script:

  1. Connects to an existing IxNetwork session (supports physical ports
     and LAGs).
  2. Builds a raw traffic item containing an SNMPv2c GET-request PDU
     (community "public", OID sysDescr.0) encapsulated in Ethernet/IPv4/UDP.
  3. Iterates over the destination MAC range, updating the MAC increment
     field and transmitting at a configured line rate for a fixed duration.
  4. Optionally SSH-connects to a Juniper router to clear and inspect
     the info-log after each block, looking for SNMP authentication
     failure entries (AUTH-5-SNMPD_AUTH_FAILURE).
  5. Generates an HTML report summarising per-block traffic statistics,
     timing, and whether any SNMP authentication errors were observed on
     the monitored router.

Usage examples:

  # Basic sweep with an existing IxNetwork session
  python3 ixnetwork_snmp_mac_sweep.py --session-id 1

  # Sweep a specific MAC range with router monitoring
  python3 ixnetwork_snmp_mac_sweep.py --session-id 1 \\
      --start-mac 00:00:00:00:00:00 --end-mac 00:00:ff:ff:ff:ff \\
      --block-size 999999999 \\
      --router 10.37.105.154 --router-user root --router-password xxxxx

  # Dry-run to preview block boundaries
  python3 ixnetwork_snmp_mac_sweep.py --dry-run --start-mac 00:00:00:00:00:00

Dependencies:
  - ixnetwork_restpy  (pip install ixnetwork-restpy)
  - paramiko          (pip install paramiko)

Author : Auto-generated with GitHub Copilot
License: MIT
"""

import sys
import os
import time
import math
import argparse
import datetime
import html as html_module
import re

import paramiko
from ixnetwork_restpy import SessionAssistant, Files

# ---------------------------------------------------------------------------
# Configuration – edit these to match your environment
# ---------------------------------------------------------------------------
IXNETWORK_HOST = "10.37.117.94"       # IxNetwork API server IP
IXNETWORK_PORT = 65263                  # REST port (443 for https, 11009 for linux API server)
CHASSIS_IP     = "10.37.105.158"       # IxNetwork chassis IP
TX_PORT        = ("10.37.105.158", 1, 3)  # (chassis, card, port) for transmit
RX_PORT        = ("10.37.105.158", 1, 4)  # (chassis, card, port) for receive

MAC_BLOCK_SIZE   = 999_999_999
TOTAL_MAC_SPACE  = 2 ** 48           # 281,474,976,710,656
SOURCE_MAC       = "00:11:22:33:44:55"
SOURCE_IP        = "193.172.1.1"
DEST_IP          = "200.1.0.1"
SNMP_COMMUNITY   = "public"

# Traffic parameters
FRAME_SIZE       = 128               # bytes
LINE_RATE_PCT    = 10                 # percent of line rate
TRANSMIT_SECONDS = 10                # seconds to transmit per block


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------
def int_to_mac(value: int) -> str:
    """Convert an integer (0 .. 2^48-1) to colon-separated MAC string."""
    value = value & 0xFFFFFFFFFFFF
    octets = []
    for _ in range(6):
        octets.append(f"{value & 0xFF:02x}")
        value >>= 8
    return ":".join(reversed(octets))


def mac_to_int(mac: str) -> int:
    """Convert a colon-separated MAC string to integer."""
    return int(mac.replace(":", "").replace("-", ""), 16)


# ---------------------------------------------------------------------------
# Build SNMP GET-request payload (SNMPv2c, sysDescr.0 OID)
# ---------------------------------------------------------------------------
def build_snmp_payload_hex() -> str:
    """
    Return a hex string representing a minimal SNMPv2c GET-request PDU.
    OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
    Community: 'public'
    """
    community = SNMP_COMMUNITY.encode().hex()
    community_len = len(SNMP_COMMUNITY)

    # OID 1.3.6.1.2.1.1.1.0 encoded as BER
    oid_bytes = "06082b06010201010100"  # OID TLV
    # Null value
    null_val = "0500"
    # VarBind: SEQUENCE { oid, null }
    varbind_content = oid_bytes + null_val
    varbind = f"30{len(bytes.fromhex(varbind_content)):02x}{varbind_content}"
    # VarBindList: SEQUENCE { varbind }
    varbind_list = f"30{len(bytes.fromhex(varbind)):02x}{varbind}"

    # Request ID (integer 1)
    request_id = "020101"
    # Error status (0)
    error_status = "020100"
    # Error index (0)
    error_index = "020100"

    # GetRequest PDU (tag 0xA0)
    pdu_content = request_id + error_status + error_index + varbind_list
    pdu = f"a0{len(bytes.fromhex(pdu_content)):02x}{pdu_content}"

    # Version: SNMPv2c = 1
    version = "020101"
    # Community string
    community_tlv = f"04{community_len:02x}{community}"

    # Full SNMP message: SEQUENCE { version, community, pdu }
    msg_content = version + community_tlv + pdu
    snmp_message = f"30{len(bytes.fromhex(msg_content)):02x}{msg_content}"

    return snmp_message


# ---------------------------------------------------------------------------
# SSH / Juniper Router helpers
# ---------------------------------------------------------------------------
SNMP_AUTH_PATTERN = re.compile(
    r"AUTH-5-SNMPD_AUTH_FAILURE.*unauthorized SNMP community from"
)


def ssh_connect(hostname, username, password, port=22):
    """Open an SSH connection to a Juniper router and return the client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"  SSH: Connecting to {hostname}:{port} as {username} ...")
    client.connect(hostname, port=port, username=username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=30)
    print(f"  SSH: Connected.")
    return client


def ssh_run_command(client, command, timeout=30):
    """Run a CLI command over SSH and return stdout as a string."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    return output


def router_clear_log(client):
    """Clear the info-log on the Juniper router."""
    print("  SSH: Clearing info-log ...")
    ssh_run_command(client, "clear log info-log")


def router_check_snmp_auth_failure(client):
    """Check info-log for SNMP auth failure pattern. Return matched lines."""
    output = ssh_run_command(client, "show log info-log")
    matched_lines = []
    for line in output.splitlines():
        if SNMP_AUTH_PATTERN.search(line):
            matched_lines.append(line.strip())
    return matched_lines


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------
def generate_html_report(report_path, start_mac, end_mac, block_size,
                         total_blocks, mac_range_size, block_results,
                         router_info=None, total_duration=0):
    """Generate a styled HTML report summarising the MAC sweep results.

    Args:
        report_path:    Filesystem path for the output HTML file.
        start_mac:      First destination MAC of the sweep range.
        end_mac:        Last destination MAC of the sweep range.
        block_size:     Number of MAC addresses per block.
        total_blocks:   Total number of blocks in the sweep.
        mac_range_size: Total number of MAC addresses in the range.
        block_results:  List of per-block result dicts (see main loop).
        router_info:    Optional dict with router SSH connection details.
        total_duration: Wall-clock seconds for the entire test run.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows_html = ""
    total_tx = 0
    total_rx = 0
    for r in block_results:
        tx = int(r["tx_frames"]) if str(r["tx_frames"]).isdigit() else 0
        rx = int(r["rx_frames"]) if str(r["rx_frames"]).isdigit() else 0
        total_tx += tx
        total_rx += rx
        try:
            loss_val = float(r.get("loss_pct", 0) or 0)
        except (ValueError, TypeError):
            loss_val = 0
        loss_class = ' class="loss"' if loss_val > 0 else ""
        warnings = r.get("snmp_warnings", [])
        warn_count = len(warnings)
        if warn_count > 0:
            row_class = ' class="snmp-warn-row"'
            warn_cell = f'<td class="snmp-warn">Yes ({warn_count})</td>'
        else:
            row_class = ""
            warn_cell = "<td>No</td>"
        rows_html += f"""        <tr{row_class}>
          <td>{r["block"]}</td>
          <td><code>{html_module.escape(r["start_mac"])}</code></td>
          <td><code>{html_module.escape(r["end_mac"])}</code></td>
          <td>{r["count"]:,}</td>
          <td>{r["tx_frames"]}</td>
          <td>{r["rx_frames"]}</td>
          <td{loss_class}>{r["loss_pct"]}</td>
          <td>{r.get("duration_str", "N/A")}</td>
          {warn_cell}
        </tr>\n"""

    # Router info section
    router_html = ""
    if router_info:
        router_html = f"""
<div class="summary">
<h2>Router Details</h2>
<table>
  <tr><td>Hostname / IP</td><td><code>{html_module.escape(router_info.get('host', 'N/A'))}</code></td></tr>
  <tr><td>Username</td><td>{html_module.escape(router_info.get('user', 'N/A'))}</td></tr>
  <tr><td>SSH Port</td><td>{router_info.get('port', 22)}</td></tr>
  <tr><td>Log Checked</td><td><code>show log info-log</code></td></tr>
  <tr><td>Pattern Monitored</td><td><code>AUTH-5-SNMPD_AUTH_FAILURE</code></td></tr>
</table>
</div>
"""

    # Format total duration
    total_mins, total_secs = divmod(int(total_duration), 60)
    total_hrs, total_mins = divmod(total_mins, 60)
    if total_hrs > 0:
        duration_display = f"{total_hrs}h {total_mins}m {total_secs}s"
    elif total_mins > 0:
        duration_display = f"{total_mins}m {total_secs}s"
    else:
        duration_display = f"{total_secs}s"

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SNMP MAC Sweep Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         margin: 2rem; background: #f5f5f5; color: #333; }}
  h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 0.5rem; }}
  .summary {{ background: #fff; padding: 1.5rem; border-radius: 8px;
              box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; }}
  .summary table {{ border-collapse: collapse; }}
  .summary td {{ padding: 0.3rem 1rem 0.3rem 0; }}
  .summary td:first-child {{ font-weight: bold; color: #555; }}
  table.results {{ width: 100%; border-collapse: collapse; background: #fff;
                   border-radius: 8px; overflow: hidden;
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
  table.results th {{ background: #16213e; color: #fff; padding: 0.75rem 1rem;
                      text-align: left; font-size: 0.9rem; }}
  table.results td {{ padding: 0.6rem 1rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  table.results tr:hover {{ background: #f0f4ff; }}
  table.results code {{ background: #eef; padding: 2px 5px; border-radius: 3px; }}
  .loss {{ color: #e74c3c; font-weight: bold; }}
  .snmp-warn {{ color: #fff; background: #e74c3c; font-weight: bold; padding: 0.5rem; }}
  .snmp-warn small {{ font-weight: normal; font-size: 0.75rem; }}
  .snmp-warn-row {{ background: #fdecea !important; }}
  .totals {{ background: #e8f5e9; font-weight: bold; }}
  .footer {{ margin-top: 2rem; font-size: 0.8rem; color: #999; }}
</style>
</head>
<body>
<h1>SNMP MAC Sweep Report</h1>

<p style="max-width: 800px; line-height: 1.6; color: #444;">
This report summarises an SNMP MAC address sweep test executed via IxNetwork.
Raw traffic containing SNMPv2c GET-request PDUs (community &ldquo;public&rdquo;,
OID sysDescr.0) was transmitted across the destination MAC range shown below.
Each block of MAC addresses was sent at a fixed line-rate for a configured
duration, and the monitored router&rsquo;s log was inspected for
<code>AUTH-5-SNMPD_AUTH_FAILURE</code> entries after every block.
</p>

<div class="summary">
<table>
  <tr><td>Generated</td><td>{timestamp}</td></tr>
  <tr><td>Start MAC</td><td><code>{html_module.escape(start_mac)}</code></td></tr>
  <tr><td>End MAC</td><td><code>{html_module.escape(end_mac)}</code></td></tr>
  <tr><td>MAC Range Size</td><td>{mac_range_size:,}</td></tr>
  <tr><td>Block Size</td><td>{block_size:,}</td></tr>
  <tr><td>Total Blocks</td><td>{total_blocks:,}</td></tr>
  <tr><td>Blocks Completed</td><td>{len(block_results)}</td></tr>
  <tr><td>Total Tx Frames</td><td>{total_tx:,}</td></tr>
  <tr><td>Total Rx Frames</td><td>{total_rx:,}</td></tr>
  <tr><td>Total Test Duration</td><td><strong>{duration_display}</strong></td></tr>
</table>
</div>

{router_html}

<table class="results">
<thead>
  <tr>
    <th>Block</th><th>Start MAC</th><th>End MAC</th>
    <th>MAC Count</th><th>Tx Frames</th><th>Rx Frames</th><th>Loss %</th><th>Duration</th><th>Found Errors<br><small>AUTH-5-SNMPD_AUTH_FAILURE:<br>nsa_log_community:<br>unauthorized SNMP community</small></th>
  </tr>
</thead>
<tbody>
{rows_html}</tbody>
</table>

<div class="footer">
  IxNetwork SNMP MAC Sweep &mdash; Report generated {timestamp} &mdash; Total duration: {duration_display}
</div>
</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(report_html)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    """Entry point: parse CLI arguments and run the SNMP MAC sweep."""
    parser = argparse.ArgumentParser(
        description="IxNetwork SNMP MAC sweep — generate raw SNMP traffic "
                    "while sweeping destination MAC addresses in blocks and "
                    "optionally monitor a Juniper router for auth failures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--host", default=IXNETWORK_HOST, help="IxNetwork API server")
    parser.add_argument("--port", type=int, default=IXNETWORK_PORT, help="REST API port")
    parser.add_argument("--session-id", type=int, default=None, help="Existing IxNetwork session ID to connect to")
    parser.add_argument("--session-name", default=None, help="Existing IxNetwork session name to connect to")
    parser.add_argument("--start-mac", default="00:00:00:00:00:00", help="First destination MAC (default 00:00:00:00:00:00)")
    parser.add_argument("--end-mac", default="ff:ff:ff:ff:ff:ff", help="Last destination MAC inclusive (default ff:ff:ff:ff:ff:ff)")
    parser.add_argument("--tx-port", default=None, help="Tx vport name or assigned port (e.g. 'TxPort' or '10.37.105.158:1:3')")
    parser.add_argument("--rx-port", default=None, help="Rx vport name or assigned port (e.g. 'RxPort' or '10.37.105.158:1:4')")
    parser.add_argument("--block-size", type=int, default=MAC_BLOCK_SIZE, help=f"MACs per block (default {MAC_BLOCK_SIZE:,})")
    parser.add_argument("--start-block", type=int, default=0, help="Block index to start from (for resuming)")
    parser.add_argument("--report", default="snmp_mac_sweep_report.html", help="HTML report output file (default: snmp_mac_sweep_report.html)")
    parser.add_argument("--router", default=None, help="Juniper router IP/hostname for SNMP auth failure checking")
    parser.add_argument("--router-user", default="admin", help="Router SSH username (default: admin)")
    parser.add_argument("--router-password", default="admin", help="Router SSH password (default: admin)")
    parser.add_argument("--router-port", type=int, default=22, help="Router SSH port (default: 22)")
    parser.add_argument("--dry-run", action="store_true", help="Print config without connecting")
    args = parser.parse_args()

    start_mac_int_global = mac_to_int(args.start_mac)
    end_mac_int_global = mac_to_int(args.end_mac)
    if end_mac_int_global < start_mac_int_global:
        print(f"Error: --end-mac ({args.end_mac}) is less than --start-mac ({args.start_mac})")
        sys.exit(1)
    block_size = args.block_size
    mac_range_size = end_mac_int_global - start_mac_int_global + 1
    total_blocks = math.ceil(mac_range_size / block_size)

    print(f"Start MAC        : {args.start_mac}")
    print(f"End MAC          : {args.end_mac}")
    print(f"MAC range size   : {mac_range_size:,}")
    print(f"Block size       : {block_size:,}")
    print(f"Total blocks     : {total_blocks:,}")
    print(f"Starting block   : {args.start_block}")
    print()

    if args.dry_run:
        for blk in range(args.start_block, min(args.start_block + 3, total_blocks)):
            offset = blk * block_size
            blk_start = start_mac_int_global + offset
            count = min(block_size, mac_range_size - offset)
            print(f"  Block {blk}: start={int_to_mac(blk_start)}  count={count:,}")
        print("  ...")
        sys.exit(0)

    # -----------------------------------------------------------------------
    # 1. Connect to existing IxNetwork session
    # -----------------------------------------------------------------------
    print(f"Connecting to existing IxNetwork session at {args.host}:{args.port} ...")
    session_kwargs = dict(
        IpAddress=args.host,
        RestPort=args.port,
        UserName="admin",
        Password="admin",
        ClearConfig=False,
    )
    if args.session_id is not None:
        session_kwargs["SessionId"] = args.session_id
        print(f"  Using session ID: {args.session_id}")
    elif args.session_name is not None:
        session_kwargs["SessionName"] = args.session_name
        print(f"  Using session name: {args.session_name}")
    else:
        # Connect to the first available existing session
        session_kwargs["SessionName"] = "snmp_mac_sweep"
        print("  No session ID/name specified, using session name 'snmp_mac_sweep'")

    session_assistant = SessionAssistant(**session_kwargs)
    ixnetwork = session_assistant.Ixnetwork
    print(f"  Connected to session: {session_assistant.Session.Name} (ID {session_assistant.Session.Id})")

    # -----------------------------------------------------------------------
    # 2. Use existing ports/LAGs from the session
    # -----------------------------------------------------------------------
    print("Using existing ports from session ...")
    vports = ixnetwork.Vport.find()
    lags = ixnetwork.Lag.find()

    print(f"  Found {len(vports)} vports, {len(lags)} LAGs")
    if lags:
        for lag in lags:
            print(f"  LAG: Name='{lag.Name}'  href={lag.href}")

    def find_port_or_lag(identifier, vports, lags):
        """Find a vport or LAG by name or AssignedTo string."""
        # Search LAGs first
        for lag in lags:
            if lag.Name == identifier:
                return lag
        # Then search vports
        for vp in vports:
            if vp.Name == identifier or vp.AssignedTo == identifier:
                return vp
        print(f"Error: No vport or LAG found matching '{identifier}'")
        print("Available LAGs:")
        for lag in lags:
            print(f"  Name='{lag.Name}'")
        print("Available vports:")
        for vp in vports:
            print(f"  Name='{vp.Name}'  AssignedTo='{vp.AssignedTo}'")
        sys.exit(1)

    if args.tx_port:
        tx_port = find_port_or_lag(args.tx_port, vports, lags)
    else:
        # Default: use first LAG if available, otherwise first vport
        tx_port = lags[0] if lags else vports[0]
    if args.rx_port:
        rx_port = find_port_or_lag(args.rx_port, vports, lags)
    else:
        rx_port = lags[1] if len(lags) > 1 else vports[1] if len(vports) > 1 else vports[0]

    tx_name = tx_port.Name
    rx_name = rx_port.Name
    print(f"  Tx: {tx_name}")
    print(f"  Rx: {rx_name}")

    # -----------------------------------------------------------------------
    # 3. Create raw traffic item with protocol stack:
    #    Ethernet II > IPv4 > UDP > Custom (SNMP payload)
    # -----------------------------------------------------------------------
    traffic = ixnetwork.Traffic

    # Remove any previous SNMP_MAC_Sweep traffic item to avoid conflicts
    for existing_ti in traffic.TrafficItem.find(Name="SNMP_MAC_Sweep"):
        print("  Removing existing SNMP_MAC_Sweep traffic item ...")
        existing_ti.remove()

    print("Creating raw traffic item ...")
    traffic_item = traffic.TrafficItem.add(
        Name="SNMP_MAC_Sweep",
        TrafficType="raw",
        BiDirectional=False,
    )

    # Endpoint set: Tx -> Rx
    # For LAGs use the LAG href directly; for vports use vport/protocols
    def get_endpoint_ref(port_obj):
        if hasattr(port_obj, 'ProtocolStack'):
            # It's a LAG — use LAG href directly
            return [port_obj.href]
        else:
            # It's a vport — use protocols path
            return [port_obj.Protocols.find().href]

    endpoint_set = traffic_item.EndpointSet.add(
        Sources=get_endpoint_ref(tx_port),
        Destinations=get_endpoint_ref(rx_port),
    )

    # Access the config element (high-level stream)
    config_element = traffic_item.ConfigElement.find()

    # -- Protocol stack --
    # By default a raw stream has Ethernet II (stack/1) and FCS (stack/2).
    # We must get the Ethernet II stack specifically (first stack, index 0).
    all_stacks = config_element.Stack.find()
    stack = all_stacks[0]  # Ethernet II header (not FCS)

    # Helper: find a protocol template by exact StackTypeId match
    # (ProtocolTemplate.find() does substring matching, so we filter manually)
    def get_template(stack_type_id):
        all_tmpls = ixnetwork.Traffic.ProtocolTemplate.find()
        for t in all_tmpls:
            if t.StackTypeId == stack_type_id:
                return t
        print(f"Error: Could not find protocol template with StackTypeId='{stack_type_id}'")
        sys.exit(1)

    # Destination MAC — will be updated per-block
    dst_mac_field = stack.Field.find(FieldTypeId="ethernet.header.destinationAddress")
    dst_mac_field.Auto = False
    dst_mac_field.ValueType = "increment"
    dst_mac_field.StartValue = "00:00:00:00:00:00"
    dst_mac_field.StepValue = "00:00:00:00:00:01"
    dst_mac_field.CountValue = str(block_size)

    # Source MAC
    src_mac_field = stack.Field.find(FieldTypeId="ethernet.header.sourceAddress")
    src_mac_field.Auto = False
    src_mac_field.ValueType = "singleValue"
    src_mac_field.SingleValue = SOURCE_MAC

    # EtherType for IPv4
    ethertype_field = stack.Field.find(FieldTypeId="ethernet.header.etherType")
    ethertype_field.Auto = False
    ethertype_field.ValueType = "singleValue"
    ethertype_field.SingleValue = "0800"

    # Add IPv4 header
    ipv4_template = get_template("ipv4")
    stack.AppendProtocol(Arg2=ipv4_template.href)
    ipv4_stack = config_element.Stack.find()[1]

    # IPv4 fields
    src_ip_field = ipv4_stack.Field.find(FieldTypeId="ipv4.header.srcIp")
    src_ip_field.Auto = False
    src_ip_field.ValueType = "singleValue"
    src_ip_field.SingleValue = SOURCE_IP

    dst_ip_field = ipv4_stack.Field.find(FieldTypeId="ipv4.header.dstIp")
    dst_ip_field.Auto = False
    dst_ip_field.ValueType = "singleValue"
    dst_ip_field.SingleValue = DEST_IP

    protocol_field = ipv4_stack.Field.find(FieldTypeId="ipv4.header.protocol")
    protocol_field.Auto = False
    protocol_field.ValueType = "singleValue"
    protocol_field.SingleValue = "17"  # UDP

    # Add UDP header
    udp_template = get_template("udp")
    ipv4_stack.AppendProtocol(Arg2=udp_template.href)
    udp_stack = config_element.Stack.find()[2]

    udp_dst_port = udp_stack.Field.find(FieldTypeId="udp.header.dstPort")
    udp_dst_port.Auto = False
    udp_dst_port.ValueType = "singleValue"
    udp_dst_port.SingleValue = "161"  # SNMP

    udp_src_port = udp_stack.Field.find(FieldTypeId="udp.header.srcPort")
    udp_src_port.Auto = False
    udp_src_port.ValueType = "singleValue"
    udp_src_port.SingleValue = "50000"

    # Add custom payload (SNMP PDU)
    snmp_hex = build_snmp_payload_hex()
    custom_template = get_template("custom")
    udp_stack.AppendProtocol(Arg2=custom_template.href)
    custom_stack = config_element.Stack.find()[3]
    # Set the custom header length (in bits) before setting data
    length_field = custom_stack.Field.find(FieldTypeId="custom.header.length")
    snmp_byte_len = len(snmp_hex) // 2
    length_field.Auto = False
    length_field.SingleValue = str(snmp_byte_len * 8)
    # Now set the custom payload bytes
    payload_field = custom_stack.Field.find(FieldTypeId="custom.header.data")
    payload_field.Auto = False
    payload_field.ValueType = "singleValue"
    payload_field.SingleValue = snmp_hex

    # -- Frame size --
    config_element.FrameSize.Type = "fixed"
    config_element.FrameSize.FixedSize = FRAME_SIZE

    # -- Transmit control --
    config_element.TransmissionControl.Type = "fixedDuration"
    config_element.TransmissionControl.Duration = TRANSMIT_SECONDS

    # -- Rate --
    config_element.FrameRate.Type = "percentLineRate"
    config_element.FrameRate.Rate = LINE_RATE_PCT

    # Enable tracking
    traffic_item.Tracking.find().TrackBy = ["trackingenabled0"]

    # -----------------------------------------------------------------------
    # 4. Connect to Juniper router (if specified)
    # -----------------------------------------------------------------------
    ssh_client = None
    if args.router:
        ssh_client = ssh_connect(args.router, args.router_user,
                                 args.router_password, args.router_port)

    # -----------------------------------------------------------------------
    # 5. Iterate over MAC blocks
    # -----------------------------------------------------------------------
    print(f"\nStarting MAC sweep from block {args.start_block} ...\n")

    block_results = []
    test_start_time = time.time()

    for block_idx in range(args.start_block, total_blocks):
        offset = block_idx * block_size
        blk_start_int = start_mac_int_global + offset
        remaining = mac_range_size - offset
        count = min(block_size, remaining)
        start_mac = int_to_mac(blk_start_int)

        print(f"[Block {block_idx}/{total_blocks}] "
              f"Dest MAC range: {start_mac} + {count:,} "
              f"(step 00:00:00:00:00:01)")

        block_start_time = time.time()

        # Clear router log before this block
        if ssh_client:
            router_clear_log(ssh_client)

        # Update destination MAC field for this block
        dst_mac_field.StartValue = start_mac
        dst_mac_field.StepValue = "00:00:00:00:00:01"
        dst_mac_field.CountValue = str(count)

        # Apply & generate traffic (with retry for transient IxNetwork errors)
        max_retries = 3
        block_failed = False
        for attempt in range(1, max_retries + 1):
            try:
                # Stop any lingering traffic before applying
                try:
                    traffic.StopStatelessTrafficBlocking()
                except Exception:
                    pass
                time.sleep(2)
                traffic_item.Generate()
                traffic.Apply()
                traffic.StartStatelessTrafficBlocking()
                break
            except Exception as exc:
                if attempt < max_retries:
                    wait = 5 * attempt  # progressive backoff: 5s, 10s
                    print(f"  *** Traffic apply/start failed (attempt {attempt}/{max_retries}): {exc}")
                    print(f"  *** Retrying in {wait} seconds ...")
                    time.sleep(wait)
                else:
                    print(f"  *** Traffic apply/start failed after {max_retries} attempts: {exc}")
                    print(f"  *** SKIPPING block {block_idx} and continuing ...")
                    block_failed = True

        if block_failed:
            block_elapsed = time.time() - block_start_time
            block_results.append({
                "block": block_idx,
                "start_mac": start_mac,
                "end_mac": int_to_mac(blk_start_int + count - 1),
                "count": count,
                "tx_frames": "SKIPPED",
                "rx_frames": "SKIPPED",
                "loss_pct": "N/A",
                "snmp_warnings": [],
                "duration_str": "FAILED",
                "duration_secs": block_elapsed,
            })
            print()
            continue

        print(f"  Traffic running for {TRANSMIT_SECONDS}s ...")
        time.sleep(TRANSMIT_SECONDS + 2)  # buffer for completion

        # Stop (in case it hasn't auto-stopped)
        try:
            traffic.StopStatelessTrafficBlocking()
        except Exception:
            pass  # already stopped after fixed duration

        # Collect stats
        flow_stats = session_assistant.StatViewAssistant("Flow Statistics")

        # Check router log for SNMP auth failures
        snmp_warnings = []
        if ssh_client:
            print("  SSH: Checking info-log for SNMP auth failures ...")
            snmp_warnings = router_check_snmp_auth_failure(ssh_client)
            if snmp_warnings:
                print(f"  *** WARNING: {len(snmp_warnings)} SNMP AUTH FAILURE(s) detected! ***")
                for w in snmp_warnings[:5]:  # show first 5
                    print(f"    {w}")
                if len(snmp_warnings) > 5:
                    print(f"    ... and {len(snmp_warnings) - 5} more")
            else:
                print("  SSH: No SNMP auth failures detected.")

        for row in flow_stats.Rows:
            tx_frames = row['Tx Frames']
            rx_frames = row['Rx Frames']
            loss_pct = row['Loss %']
            block_elapsed = time.time() - block_start_time
            block_mins, block_secs = divmod(int(block_elapsed), 60)
            duration_str = f"{block_mins}m {block_secs}s" if block_mins else f"{block_secs}s"
            print(f"  Tx Frames: {tx_frames:<12}  "
                  f"Rx Frames: {rx_frames:<12}  "
                  f"Loss %: {loss_pct}  "
                  f"Duration: {duration_str}")
            block_results.append({
                "block": block_idx,
                "start_mac": start_mac,
                "end_mac": int_to_mac(blk_start_int + count - 1),
                "count": count,
                "tx_frames": tx_frames,
                "rx_frames": rx_frames,
                "loss_pct": loss_pct,
                "snmp_warnings": snmp_warnings,
                "duration_str": duration_str,
                "duration_secs": block_elapsed,
            })

        print()

    # -----------------------------------------------------------------------
    # 6. Generate HTML report & cleanup
    # -----------------------------------------------------------------------
    if ssh_client:
        ssh_client.close()
        print("SSH connection closed.")

    total_duration = time.time() - test_start_time
    total_m, total_s = divmod(int(total_duration), 60)
    print(f"MAC sweep complete. Total duration: {total_m}m {total_s}s")

    router_info = None
    if args.router:
        router_info = {
            "host": args.router,
            "user": args.router_user,
            "port": args.router_port,
        }

    report_path = os.path.abspath(args.report)
    generate_html_report(
        report_path=report_path,
        start_mac=args.start_mac,
        end_mac=args.end_mac,
        block_size=block_size,
        total_blocks=total_blocks,
        mac_range_size=mac_range_size,
        block_results=block_results,
        router_info=router_info,
        total_duration=total_duration,
    )
    print(f"HTML report saved to: {report_path}")
    print(f"Open report: file://{report_path}")
    print("Done.")


if __name__ == "__main__":
    main()
