#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ipaddress
import json
import time
import re
import socket
import concurrent.futures
import subprocess
import shutil
import asyncio

import paramiko

try:
    from pysnmp.hlapi.v1arch.asyncio import (
        SnmpDispatcher,
        CommunityData,
        UdpTransportTarget,
        get_cmd,
    )
except ImportError:
    SnmpDispatcher = None
    CommunityData = None
    UdpTransportTarget = None
    get_cmd = None

from database import (
    init_db,
    upsert_device,
    log_scan,
    is_blacklisted,
    list_manual_ips,
)


# ============================================================
# Configuration
# ============================================================

NETWORK = os.getenv(
    "SCAN_NETWORK",
    "172.17.240.0/20",
)

SSH_PORT = int(
    os.getenv("SSH_PORT", "22")
)

SSH_TIMEOUT = int(
    os.getenv("SSH_TIMEOUT", "10")
)

SCAN_WORKERS = int(
    os.getenv("SCAN_WORKERS", "40")
)

LEGACY_SSH_FALLBACK = os.getenv(
    "LEGACY_SSH_FALLBACK",
    "1",
).strip().lower() in (
    "1", "true", "yes", "on",
)

# ------------------------------------------------------------
# SNMP
# ------------------------------------------------------------

SNMP_ENABLED = os.getenv(
    "SNMP_ENABLED",
    "1",
).strip().lower() in (
    "1", "true", "yes", "on",
)

SNMP_PORT = int(
    os.getenv("SNMP_PORT", "161")
)

SNMP_VERSION = os.getenv(
    "SNMP_VERSION",
    "2c",
).strip().lower()

SNMP_TIMEOUT = float(
    os.getenv("SNMP_TIMEOUT", "2.5")
)

SNMP_RETRIES = int(
    os.getenv("SNMP_RETRIES", "1")
)

SNMP_COMMUNITY = os.getenv(
    "SNMP_COMMUNITY",
    "ngstehwl",
)

SNMP_CREDENTIALS = [
    {
        "id": "default",
        "community": SNMP_COMMUNITY,
    }
]
# ============================================================
# Helpers
# ============================================================


def safe_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value).strip()


def missing(value):
    if value is None:
        return True
    return not str(value).strip() or str(value).strip() in {
        "-",
        "--",
        "N/A",
        "n/a",
        "unknown",
        "Unknown",
        "none",
        "None",
    }


def first_nonempty(*values):
    for value in values:
        if not missing(value):
            return str(value).strip()
    return ""


def normalize_number_unit(value, default_unit=""):
    value = safe_text(value)
    if not value:
        return ""
    if default_unit and re.fullmatch(r"-?\d+(?:\.\d+)?", value):
        return f"{value} {default_unit}"
    return value


def parse_key_values(text):
    """Parse RouterOS-style key=value and key: value data."""
    out = {}
    if not text:
        return out

    # The pattern above intentionally also allows plain values.  For
    # RouterOS output, line-by-line parsing is more reliable for quoted
    # strings containing spaces.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        for m in re.finditer(
            r"([A-Za-z][A-Za-z0-9_.-]*)\s*(?:=|:)\s*"
            r"(?:\"([^\"]*)\"|'([^']*)'|([^\s;]+))",
            line,
        ):
            key = m.group(1).lower()
            value = next(
                (
                    x for x in (m.group(2), m.group(3), m.group(4))
                    if x is not None
                ),
                "",
            )
            out[key] = value.strip()

    return out


def first_value(text, *keys):
    if not text:
        return ""

    kv = parse_key_values(text)
    for key in keys:
        value = kv.get(str(key).lower())
        if not missing(value):
            return value

    # Fallback for lines such as "Version: 7.14" or "name: router".
    for key in keys:
        pattern = re.compile(
            rf"^\s*{re.escape(str(key))}\s*[:=]\s*(.+?)\s*$",
            re.I | re.M,
        )
        match = pattern.search(text)
        if match:
            return match.group(1).strip().strip("\"'")

    return ""


def normalize_mac(value):
    value = safe_text(value)
    if not value:
        return ""

    # RouterOS often returns AA:BB:CC:DD:EE:FF directly.
    if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value):
        return value.upper()

    # SNMP may return 6 raw octets as a printable representation.
    hex_pairs = re.findall(r"[0-9A-Fa-f]{2}", value)
    if len(hex_pairs) == 6:
        return ":".join(x.upper() for x in hex_pairs)

    # Cisco style xxxx.xxxx.xxxx
    if re.fullmatch(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}", value):
        raw = value.replace(".", "")
        return ":".join(
            raw[i:i + 2].upper()
            for i in range(0, 12, 2)
        )

    return value


def merge_missing(data, extra):
    """Fill only empty fields; existing SSH data wins."""
    for key, value in (extra or {}).items():
        if key.startswith("_"):
            continue
        if not missing(value) and missing(data.get(key)):
            data[key] = value
    return data


# ============================================================
# Credential Handling - SSH
# ============================================================


def _credentials():
    out = []

    try:
        raw = os.getenv(
            "SSH_CREDENTIALS_JSON",
            "",
        ).strip()
        if raw:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    username = str(
                        item.get("username", "")
                    ).strip()
                    password = str(
                        item.get("password", "")
                    )
                    if username:
                        out.append({
                            "username": username,
                            "password": password,
                            "id": item.get(
                                "id",
                                f"json-{len(out)+1}",
                            ),
                        })
    except Exception:
        pass

    for i in range(1, 11):
        username = os.getenv(
            f"SSH_USER_{i}",
            "",
        ).strip()
        password = os.getenv(
            f"SSH_PASS_{i}",
            "",
        )
        if username:
            out.append({
                "username": username,
                "password": password,
                "id": f"cred-{i}",
            })

    username = os.getenv(
        "SSH_USER",
        "",
    ).strip()
    password = os.getenv(
        "SSH_PASS",
        "",
    )
    if username:
        out.append({
            "username": username,
            "password": password,
            "id": "default",
        })

    uniq = []
    seen = set()
    for credential in out:
        key = (
            credential.get("username", ""),
            credential.get("password", ""),
        )
        if key not in seen and key[0]:
            uniq.append(credential)
            seen.add(key)

    return uniq


CREDENTIALS = _credentials()


# ============================================================
# Credential Handling - SNMP
# ============================================================


def _snmp_credentials():
    out = []

    raw = os.getenv(
        "SNMP_COMMUNITIES_JSON",
        "",
    ).strip()

    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str):
                        community = item.strip()
                        if community:
                            out.append({
                                "community": community,
                                "id": f"json-{len(out)+1}",
                            })
                    elif isinstance(item, dict):
                        community = str(
                            item.get("community", "")
                        ).strip()
                        if community:
                            out.append({
                                "community": community,
                                "id": item.get(
                                    "id",
                                    f"json-{len(out)+1}",
                                ),
                            })
        except Exception:
            pass

    if SNMP_COMMUNITY.strip():
        out.append({
            "community": SNMP_COMMUNITY.strip(),
            "id": "default",
        })

    uniq = []
    seen = set()
    for item in out:
        community = item["community"]
        if community not in seen:
            uniq.append(item)
            seen.add(community)

    return uniq


SNMP_CREDENTIALS = _snmp_credentials()


# ============================================================
# IP List
# ============================================================


def get_all_ips():
    net = ipaddress.ip_network(
        NETWORK,
        strict=False,
    )

    ips = [
        str(ip)
        for ip in net.hosts()
        if not is_blacklisted(str(ip))
    ]

    for row in list_manual_ips():
        ip = row["ip_address"]
        if (
            row["enabled"]
            and not is_blacklisted(ip)
            and ip not in ips
        ):
            ips.append(ip)

    return ips


# ============================================================
# Port / Host Alive Check
# ============================================================


def port_is_open(ip, port, timeout=1):
    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout,
        ):
            return True
    except Exception:
        return False


def host_is_alive(ip):
    """
    Consider host alive if:
    1) SSH TCP port is open, or
    2) ICMP ping responds.

    SNMP is UDP, so it must NOT be checked with
    port_is_open() / TCP socket connection.
    """

    # --------------------------------------------------------
    # 1) SSH devices
    # --------------------------------------------------------
    if port_is_open(
        ip,
        SSH_PORT,
        timeout=1,
    ):
        return True

    # --------------------------------------------------------
    # 2) ICMP
    # --------------------------------------------------------
    try:
        result = subprocess.run(
            [
                "ping",
                "-c",
                "1",
                "-W",
                "1",
                ip,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )

        if result.returncode == 0:
            return True

    except Exception:
        pass

    return False
# ============================================================
# Legacy OpenSSH Availability
# ============================================================


def legacy_ssh_available():
    return (
        LEGACY_SSH_FALLBACK
        and shutil.which("ssh") is not None
        and shutil.which("sshpass") is not None
    )


# ============================================================
# Legacy SSH Client
# ============================================================


class LegacySSHClient:
    def __init__(self, ip, username, password):
        self.ip = ip
        self.username = username
        self.password = password

    def exec_command(self, command, timeout=8):
        env = os.environ.copy()
        env["SSHPASS"] = self.password

        ssh_options = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", f"ConnectTimeout={SSH_TIMEOUT}",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=2",
            "-o", "PreferredAuthentications=password",
            "-o", "PasswordAuthentication=yes",
            "-o", "PubkeyAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "HostKeyAlgorithms=+ssh-rsa,ssh-dss",
            "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1",
            "-o", "Ciphers=+aes128-cbc,3des-cbc,aes256-cbc",
            "-o", "MACs=+hmac-sha1,hmac-sha1-96",
            "-o", "Compression=no",
            "-p", str(SSH_PORT),
        ]

        cmd = [
            "sshpass",
            "-e",
            "ssh",
            *ssh_options,
            f"{self.username}@{self.ip}",
            command,
        ]

        try:
            result = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=max(timeout, SSH_TIMEOUT) + 5,
            )
            return (
                None,
                _LegacyOutput(result.stdout or ""),
                _LegacyOutput(result.stderr or ""),
            )
        except subprocess.TimeoutExpired as e:
            return (
                None,
                _LegacyOutput(e.stdout or ""),
                _LegacyOutput(e.stderr or ""),
            )
        except Exception:
            return (
                None,
                _LegacyOutput(""),
                _LegacyOutput(""),
            )

    def close(self):
        return None


class _LegacyOutput:
    def __init__(self, text):
        self.text = (
            text
            if isinstance(text, str)
            else str(text or "")
        )

    def read(self):
        return self.text.encode(
            "utf-8",
            "replace",
        )


# ============================================================
# SSH Connection
# ============================================================


def ssh_connect_normal(ip, credential):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )
    client.connect(
        ip,
        port=SSH_PORT,
        username=credential["username"],
        password=credential["password"],
        timeout=SSH_TIMEOUT,
        banner_timeout=SSH_TIMEOUT,
        auth_timeout=SSH_TIMEOUT,
        allow_agent=False,
        look_for_keys=False,
        compress=False,
    )
    return client


def ssh_connect_legacy(ip, credential):
    if not legacy_ssh_available():
        raise RuntimeError(
            "Legacy SSH unavailable: ssh/sshpass not installed"
        )

    client = LegacySSHClient(
        ip,
        credential["username"],
        credential["password"],
    )

    _, stdout, stderr = client.exec_command(
        "/system identity print",
        timeout=SSH_TIMEOUT,
    )

    output = stdout.read().decode(
        "utf-8",
        "replace",
    ).strip()

    error_output = stderr.read().decode(
        "utf-8",
        "replace",
    ).strip()

    if not output:
        if error_output:
            raise RuntimeError(
                "Legacy SSH failed: "
                + error_output[:180]
            )
        raise RuntimeError("Legacy SSH failed")

    return client


def ssh_connect(ip):
    last_error = None

    if not CREDENTIALS:
        raise ValueError(
            "No SSH credentials configured"
        )

    for credential in CREDENTIALS:
        try:
            client = ssh_connect_normal(
                ip,
                credential,
            )
            return (
                client,
                f"normal:{credential.get('id', credential['username'])}",
            )
        except Exception as e:
            last_error = e
            try:
                client.close()
            except Exception:
                pass

        if LEGACY_SSH_FALLBACK:
            try:
                client = ssh_connect_legacy(
                    ip,
                    credential,
                )
                return (
                    client,
                    f"legacy:{credential.get('id', credential['username'])}",
                )
            except Exception as e:
                last_error = e

    raise (
        last_error
        or RuntimeError("SSH connection failed")
    )


# ============================================================
# Execute SSH Command
# ============================================================


def run_cmd(client, command, timeout=8):
    try:
        _, stdout, _ = client.exec_command(
            command,
            timeout=timeout,
        )
        return stdout.read().decode(
            "utf-8",
            "replace",
        ).strip()
    except Exception:
        return ""


# ============================================================
# SNMP low-level helpers
# ============================================================


async def _snmp_get_async(ip, community, oids, version="2c"):
    if not SNMP_ENABLED or SnmpDispatcher is None:
        return {}

    results = {}
    mp_model = 0 if str(version).lower() in {"1", "v1"} else 1

    async with _snmp_dispatcher_context() as dispatcher:
        target = await UdpTransportTarget.create(
            (ip, SNMP_PORT),
            timeout=SNMP_TIMEOUT,
            retries=SNMP_RETRIES,
        )

        iterator = await get_cmd(
            dispatcher,
            CommunityData(
                community,
                mpModel=mp_model,
            ),
            target,
            *[
                (oid, None)
                for oid in oids
            ],
        )

        error_indication, error_status, error_index, var_binds = iterator

        if error_indication or error_status:
            return {}

        for oid, value in var_binds:
            results[safe_text(oid)] = safe_text(
                value.prettyPrint()
                if hasattr(value, "prettyPrint")
                else value
            )

    return results


class _snmp_dispatcher_context:
    """Compatibility context for PySNMP v7 v1arch SnmpDispatcher."""

    async def __aenter__(self):
        self.dispatcher = SnmpDispatcher()
        return self.dispatcher

    async def __aexit__(self, exc_type, exc, tb):
        try:
            self.dispatcher.close_dispatcher()
        except Exception:
            try:
                self.dispatcher.transport_dispatcher.close_dispatcher()
            except Exception:
                pass


def snmp_get(ip, oids, credentials=None):
    if not SNMP_ENABLED:
        return {
            "values": {},
            "credential_id": "",
            "community": "",
        }

    if SnmpDispatcher is None:
        return {
            "values": {},
            "credential_id": "",
            "community": "",
            "error": "pysnmp not installed",
        }

    credentials = credentials or SNMP_CREDENTIALS

    for credential in credentials:
        community = credential["community"]
        try:
            values = asyncio.run(
                _snmp_get_async(
                    ip,
                    community,
                    oids,
                    version=SNMP_VERSION,
                )
            )
            if values:
                return {
                    "values": values,
                    "credential_id": credential.get(
                        "id", "snmp"
                    ),
                    "community": community,
                }
        except Exception:
            continue

    return {
        "values": {},
        "credential_id": "",
        "community": "",
    }


# ============================================================
# SNMP OIDs
# ============================================================

SNMP_OIDS = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "ifName.1": "1.3.6.1.2.1.31.1.1.1.1.1",
    "ifDescr.1": "1.3.6.1.2.1.2.2.1.2.1",
    "ifPhysAddress.1": "1.3.6.1.2.1.2.2.1.6.1",
}


def snmp_standard_info(ip):
    result = snmp_get(
        ip,
        list(SNMP_OIDS.values()),
    )

    values = result.get("values", {})
    by_name = {}
    reverse = {
        oid: name
        for name, oid in SNMP_OIDS.items()
    }

    for oid, value in values.items():
        key = reverse.get(oid, oid)
        by_name[key] = value

    data = {}
    data["hostname"] = first_nonempty(
        by_name.get("sysName")
    )
    data["firmware_version"] = first_nonempty(
        by_name.get("sysDescr")
    )
    data["uptime"] = first_nonempty(
        by_name.get("sysUpTime")
    )
    data["mac_address"] = normalize_mac(
        first_nonempty(
            by_name.get("ifPhysAddress.1")
        )
    )

    raw = {
        "system": by_name,
        "credential_id": result.get("credential_id"),
    }

    return data, raw, result


# ============================================================
# Mimosa C5c SNMP
# ============================================================

MIMOSA_C5C_OIDS = {
    "device_name": "1.3.6.1.4.1.43356.2.1.2.1.1.0",
    "serial_number": "1.3.6.1.4.1.43356.2.1.2.1.2.0",
    "firmware": "1.3.6.1.4.1.43356.2.1.2.1.3.0",
    "temperature": "1.3.6.1.4.1.43356.2.1.2.1.8.0",

    "ssid": "1.3.6.1.4.1.43356.2.1.2.3.1.0",
    "wan_mac": "1.3.6.1.4.1.43356.2.1.2.3.2.0",

    "wireless_mode": "1.3.6.1.4.1.43356.2.1.2.4.1.0",

    "local_ip": "1.3.6.1.4.1.43356.2.1.2.5.8.0",

    # RF chain 1/2
    "tx_power_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.2.1",
    "tx_power_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.2.2",

    "rx_power_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.3.1",
    "rx_power_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.3.2",

    "rx_noise_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.4.1",
    "rx_noise_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.4.2",

    "snr_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.5.1",
    "snr_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.5.2",

    "frequency_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.6.1",
    "frequency_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.6.2",

    "polarization_1": "1.3.6.1.4.1.43356.2.1.2.6.1.1.7.1",
    "polarization_2": "1.3.6.1.4.1.43356.2.1.2.6.1.1.7.2",

    # PHY
    "tx_phy_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.2.1",
    "tx_phy_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.2.2",

    "tx_mcs_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.3.1",
    "tx_mcs_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.3.2",

    "rx_phy_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.5.1",
    "rx_phy_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.5.2",

    "rx_mcs_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.6.1",
    "rx_mcs_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.6.2",

    "chain_power_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.8.1",
    "chain_power_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.8.2",

    # Channel
    "channel_width": "1.3.6.1.4.1.43356.2.1.2.6.3.1.3.1",
    "channel_tx_power": "1.3.6.1.4.1.43356.2.1.2.6.3.1.4.1",
    "channel_frequency": "1.3.6.1.4.1.43356.2.1.2.6.3.1.5.1",

    # Link
    "phy_tx_rate": "1.3.6.1.4.1.43356.2.1.2.7.1.0",
    "phy_rx_rate": "1.3.6.1.4.1.43356.2.1.2.7.2.0",
    "per_tx": "1.3.6.1.4.1.43356.2.1.2.7.3.0",
    "per_rx": "1.3.6.1.4.1.43356.2.1.2.7.4.0",
}


def _mimosa_number(value):
    """
    Convert SNMP INTEGER/STRING safely to float/int.
    """
    if value is None or missing(value):
        return None

    text = safe_text(value).strip()

    # Remove common wrappers if returned by SNMP helper
    text = text.replace("INTEGER:", "").strip()

    try:
        if "." in text:
            return float(text)
        return int(text)
    except (TypeError, ValueError):
        return None


def _mimosa_scaled(value, divisor=10):
    """
    Mimosa stores several RF values multiplied by 10.
    Example:
        210  -> 21.0 dBm
       -689  -> -68.9 dBm
        158  -> 15.8 dB
    """
    number = _mimosa_number(value)

    if number is None:
        return None

    return number / divisor


def _mimosa_format(value, unit=None, divisor=None):
    """
    Format Mimosa SNMP values consistently.
    """
    if value is None or missing(value):
        return None

    if divisor is not None:
        number = _mimosa_scaled(value, divisor)
        if number is None:
            return None
    else:
        number = _mimosa_number(value)

        if number is None:
            text = safe_text(value).strip()
            return text if text else None

    if isinstance(number, float):
        if number.is_integer():
            text = str(int(number))
        else:
            text = f"{number:.1f}"
    else:
        text = str(number)

    if unit:
        return f"{text} {unit}"

    return text


def _mimosa_average(v1, v2, divisor=10):
    """
    Average chain values such as RX power, noise and SNR.
    """
    n1 = _mimosa_number(v1)
    n2 = _mimosa_number(v2)

    values = []

    if n1 is not None:
        values.append(n1)

    if n2 is not None:
        values.append(n2)

    if not values:
        return None

    return sum(values) / len(values) / divisor


def mimosa_c5c_snmp_radio(ip):
    """
    Read Mimosa/Airspan C5c values directly through SNMP.

    No SSH is required.
    """

    query_oids = list(MIMOSA_C5C_OIDS.values())

    result = snmp_get(
        ip,
        query_oids,
    )

    values = result.get("values", {})

    if not values:
        return {}, {
            "snmp": result,
            "queried_oids": MIMOSA_C5C_OIDS,
        }

    def get(name):
        oid = MIMOSA_C5C_OIDS.get(name)
        if not oid:
            return None
        return values.get(oid)

    data = {}

    # --------------------------------------------------------
    # Identification
    # --------------------------------------------------------

    device_name = get("device_name")
    serial_number = get("serial_number")
    firmware = get("firmware")

    if not missing(device_name):
        data["hostname"] = safe_text(device_name)

    if not missing(serial_number):
        data["serial_number"] = safe_text(serial_number)

    if not missing(firmware):
        data["firmware_version"] = safe_text(firmware)

    # C5c model
    data["model"] = "C5c"
    data["vendor"] = "Mimosa"

    # --------------------------------------------------------
    # Temperature
    # --------------------------------------------------------

    temperature = _mimosa_number(
        get("temperature")
    )

    if temperature is not None:
        # SNMP example: 540 => 54.0 C
        data["temperature"] = (
            f"{temperature / 10:.1f} C"
        )

    # --------------------------------------------------------
    # SSID / MAC / IP / mode
    # --------------------------------------------------------

    ssid = get("ssid")
    if not missing(ssid):
        data["ssid"] = safe_text(ssid)

    mac = get("wan_mac")
    if not missing(mac):
        data["mac_address"] = normalize_mac(
            safe_text(mac)
        )

    local_ip = get("local_ip")
    if not missing(local_ip):
        data["device_ip"] = safe_text(local_ip)

    wireless_mode = get("wireless_mode")
    if not missing(wireless_mode):
        data["mode"] = safe_text(wireless_mode)

    # --------------------------------------------------------
    # RF chain values
    # --------------------------------------------------------

    tx1 = get("tx_power_1")
    tx2 = get("tx_power_2")

    rx1 = get("rx_power_1")
    rx2 = get("rx_power_2")

    noise1 = get("rx_noise_1")
    noise2 = get("rx_noise_2")

    snr1 = get("snr_1")
    snr2 = get("snr_2")

    # Chain 1
    if not missing(tx1):
        data["tx_power_chain1"] = _mimosa_format(
            tx1,
            "dBm",
            divisor=10,
        )

    if not missing(rx1):
        data["receive_power_chain1"] = _mimosa_format(
            rx1,
            "dBm",
            divisor=10,
        )

    if not missing(noise1):
        data["noise_floor_chain1"] = _mimosa_format(
            noise1,
            "dBm",
            divisor=10,
        )

    if not missing(snr1):
        data["snr_chain1"] = _mimosa_format(
            snr1,
            "dB",
            divisor=10,
        )

    # Chain 2
    if not missing(tx2):
        data["tx_power_chain2"] = _mimosa_format(
            tx2,
            "dBm",
            divisor=10,
        )

    if not missing(rx2):
        data["receive_power_chain2"] = _mimosa_format(
            rx2,
            "dBm",
            divisor=10,
        )

    if not missing(noise2):
        data["noise_floor_chain2"] = _mimosa_format(
            noise2,
            "dBm",
            divisor=10,
        )

    if not missing(snr2):
        data["snr_chain2"] = _mimosa_format(
            snr2,
            "dB",
            divisor=10,
        )

    # --------------------------------------------------------
    # Average values for existing dashboard fields
    # --------------------------------------------------------

    avg_rx = _mimosa_average(
        rx1,
        rx2,
        divisor=10,
    )

    avg_noise = _mimosa_average(
        noise1,
        noise2,
        divisor=10,
    )

    avg_snr = _mimosa_average(
        snr1,
        snr2,
        divisor=10,
    )

    avg_tx = _mimosa_average(
        tx1,
        tx2,
        divisor=10,
    )

    if avg_tx is not None:
        data["tx_power"] = f"{avg_tx:.1f} dBm"



    if avg_rx is not None:
        data["receive_power"] = f"{avg_rx:.1f} dBm"
        data["rx_power"] = f"{avg_rx:.1f} dBm"
        data["signal_strength"] = f"{avg_rx:.1f} dBm"


    if avg_noise is not None:
        data["noise_floor"] = f"{avg_noise:.1f} dBm"

    if avg_snr is not None:
        data["snr"] = f"{avg_snr:.1f} dB"

    # --------------------------------------------------------
    # Frequency / bandwidth
    # --------------------------------------------------------

    frequency = get("channel_frequency")

    if missing(frequency):
        frequency = get("frequency_1")

    if not missing(frequency):
        data["frequency"] = _mimosa_format(
            frequency,
            "MHz",
        )

    bandwidth = get("channel_width")

    if not missing(bandwidth):
        data["bandwidth"] = _mimosa_format(
            bandwidth,
            "MHz",
        )

    channel_tx_power = get("channel_tx_power")

    if not missing(channel_tx_power):
        data["channel_tx_power"] = _mimosa_format(
            channel_tx_power,
            "dBm",
        )

    # --------------------------------------------------------
    # PHY / MCS
    # --------------------------------------------------------

    tx_phy = get("tx_phy_1")

    if not missing(tx_phy):
        data["tx_phy"] = safe_text(tx_phy)

    rx_phy = get("rx_phy_1")

    if not missing(rx_phy):
        data["rx_phy"] = safe_text(rx_phy)

    tx_mcs = get("tx_mcs_1")

    if not missing(tx_mcs):
        data["tx_mcs"] = safe_text(tx_mcs)

    rx_mcs = get("rx_mcs_1")

    if not missing(rx_mcs):
        data["rx_mcs"] = safe_text(rx_mcs)

    # --------------------------------------------------------
    # PHY rates / PER
    # --------------------------------------------------------

    tx_rate = _mimosa_number(
        get("phy_tx_rate")
    )

    rx_rate = _mimosa_number(
        get("phy_rx_rate")
    )

    if tx_rate is not None:
        data["tx_rate"] = str(tx_rate)

    if rx_rate is not None:
        data["rx_rate"] = str(rx_rate)

    per_tx = _mimosa_number(
        get("per_tx")
    )

    per_rx = _mimosa_number(
        get("per_rx")
    )

    if per_tx is not None:
        data["per_tx"] = str(per_tx)

    if per_rx is not None:
        data["per_rx"] = str(per_rx)

    # --------------------------------------------------------
    # Raw/debug data
    # --------------------------------------------------------

    raw = {
        "device_type": "mimosa_c5c",
        "queried_oids": MIMOSA_C5C_OIDS,
        "snmp": result,
    }

    return data, raw




def detect_mimosa_c5c(ip):
    """
    Detect Mimosa/Airspan C5c using standard SNMP.
    """

    result = snmp_get(
        ip,
        [
            SNMP_OIDS["sysDescr"],
            SNMP_OIDS["sysObjectID"],
        ],
    )

    values = result.get("values", {})

    sys_descr = safe_text(
        values.get(
            SNMP_OIDS["sysDescr"],
            ""
        )
    ).strip()

    sys_object_id = safe_text(
        values.get(
            SNMP_OIDS["sysObjectID"],
            ""
        )
    ).strip()

    sys_descr_lower = sys_descr.lower()

    is_mimosa = (
        "airspan-c5c" in sys_descr_lower
        or "mimosa" in sys_descr_lower
    )

    is_mimosa_oid = (
        "1.3.6.1.4.1.43356" in sys_object_id
    )

    return {
        "is_mimosa": (
            is_mimosa
            or is_mimosa_oid
        ),
        "sys_descr": sys_descr,
        "sys_object_id": sys_object_id,
        "result": result,
    }
# ============================================================
# MikroTik dynamic SNMP OID discovery via SSH
# ============================================================


def parse_print_oid(text):
    """Extract key=.oid pairs from RouterOS 'print oid' output."""
    out = {}
    if not text:
        return out

    for match in re.finditer(
        r"([A-Za-z][A-Za-z0-9_-]*)"
        r"\s*=\s*\.?([0-9]+(?:\.[0-9]+)+)",
        text,
    ):
        key = match.group(1).lower()
        oid = match.group(2)
        out[key] = oid

    return out


def mikrotik_radio_oids(client):
    candidates = [
        "/interface wireless print oid",
        "/interface wifi print oid",
    ]

    discovered = {}
    raw = {}

    for command in candidates:
        output = run_cmd(client, command)
        if output:
            raw[command] = output
            parsed = parse_print_oid(output)
            if parsed:
                discovered.update(parsed)

    return discovered, raw


def mikrotik_snmp_radio(client, ip):
    """Use RouterOS print oid output to query device-specific SNMP values."""
    oids, raw_oid = mikrotik_radio_oids(client)
    if not oids:
        return {}, {"oid_discovery": raw_oid}

    wanted = {
        "tx_power": ["tx-power", "txpower"],
        "receive_power": ["rx-power", "receive-power", "rxpower"],
        "signal_strength": ["signal-strength", "signal"],
        "noise_floor": ["noise-floor"],
        "ccq": ["ccq"],
        "frequency": ["frequency"],
        "channel": ["channel"],
        "bandwidth": [
            "bandwidth",
            "channel-width",
            "channel-widths",
        ],
        "mode": ["mode"],
        "ssid": ["ssid"],
        "mac_address": ["mac-address"],
    }

    query_oids = []
    mapping = {}

    for field, names in wanted.items():
        for name in names:
            oid = oids.get(name)
            if oid:
                query_oids.append(oid)
                mapping[oid] = field
                break

    if not query_oids:
        return {}, {"oid_discovery": raw_oid}

    result = snmp_get(
        ip,
        query_oids,
    )

    data = {}
    for oid, value in result.get("values", {}).items():
        field = mapping.get(oid)
        if not field or missing(value):
            continue

        value = safe_text(value)

        if field == "mac_address":
            value = normalize_mac(value)

        if field in {
            "tx_power",
            "receive_power",
            "signal_strength",
            "noise_floor",
        }:
            # Don't append a unit if the RouterOS SNMP object already carries one.
            if field == "signal_strength":
                value = normalize_number_unit(value, "dBm")
            elif field == "receive_power":
                value = normalize_number_unit(value, "dBm")
            elif field == "tx_power":
                value = normalize_number_unit(value, "dBm")
            elif field == "noise_floor":
                value = normalize_number_unit(value, "dBm")

        data[field] = value

    raw = {
        "oid_discovery": raw_oid,
        "queried_oids": mapping,
        "snmp": result,
    }

    return data, raw


# ============================================================
# MikroTik SSH Wireless Monitor
# ============================================================


def mikrotik_wireless_monitor(client):
    commands = [
        "/interface wireless monitor [find] once",
        "/interface wifi monitor [find] once",
    ]

    raw = {}
    merged = {}

    for command in commands:
        output = run_cmd(client, command, timeout=8)
        if output:
            raw[command] = output
            merged.update(parse_key_values(output))

    data = {}

    data["ssid"] = first_nonempty(
        merged.get("ssid"),
    )
    data["frequency"] = first_nonempty(
        merged.get("frequency"),
    )
    data["tx_power"] = first_nonempty(
        merged.get("tx-power"),
        merged.get("txpower"),
        merged.get("output-power"),
    )
    data["receive_power"] = first_nonempty(
        merged.get("rx-power"),
        merged.get("receive-power"),
    )
    data["signal_strength"] = first_nonempty(
        merged.get("signal-strength"),
        merged.get("signal"),
    )
    data["channel"] = first_nonempty(
        merged.get("channel"),
    )
    data["bandwidth"] = first_nonempty(
        merged.get("bandwidth"),
        merged.get("channel-width"),
        merged.get("channel-widths"),
    )
    data["mode"] = first_nonempty(
        merged.get("mode"),
    )
    data["noise_floor"] = first_nonempty(
        merged.get("noise-floor"),
    )
    data["ccq"] = first_nonempty(
        merged.get("ccq"),
    )
    data["tx_rate"] = first_nonempty(
        merged.get("tx-rate"),
    )
    data["rx_rate"] = first_nonempty(
        merged.get("rx-rate"),
    )
    data["mac_address"] = normalize_mac(
        first_nonempty(
            merged.get("mac-address"),
        )
    )

    data = {
        key: value
        for key, value in data.items()
        if not missing(value)
    }

    return data, raw


# ============================================================
# MikroTik
# ============================================================


def routeros_info(ip, client):
    data = {
        "ip_address": ip,
        "device_type": "MikroTik",
        "vendor": "MikroTik",
    }

    # --------------------------------------------------------
    # Identity / Resource
    # --------------------------------------------------------

    identity = run_cmd(
        client,
        "/system identity print",
    )

    resource = run_cmd(
        client,
        "/system resource print",
    )

    data["hostname"] = first_value(
        identity,
        "name",
        "identity",
    )

    data["model"] = first_value(
        resource,
        "board-name",
        "platform",
    )

    data["firmware_version"] = first_value(
        resource,
        "version",
        "routeros",
    )

    data["uptime"] = first_value(
        resource,
        "uptime",
    )

    # --------------------------------------------------------
    # CPU / Memory / Health
    # --------------------------------------------------------

    health = run_cmd(
        client,
        "/system health print",
    )

    data["cpu_memory"] = json.dumps(
        {
            "resource": resource,
            "health": health,
        },
        ensure_ascii=False,
    )

    # --------------------------------------------------------
    # Wireless / WiFi v6/v7
    # --------------------------------------------------------

    wireless = run_cmd(
        client,
        "/interface wireless print detail without-paging",
    )

    wifi = ""
    if not wireless:
        wifi = run_cmd(
            client,
            "/interface wifi print detail without-paging",
        )

    raw_wireless = wireless or wifi

    kv = parse_key_values(raw_wireless)

    data["ssid"] = kv.get("ssid", "")
    data["frequency"] = kv.get("frequency", "")
    data["tx_power"] = first_nonempty(
        kv.get("tx-power"),
        kv.get("tx-power-mode"),
    )
    data["mac_address"] = normalize_mac(
        kv.get("mac-address", "")
    )
    data["interface_name"] = kv.get("name", "")
    data["channel"] = kv.get("channel", "")
    data["bandwidth"] = first_nonempty(
        kv.get("bandwidth"),
        kv.get("channel-width"),
        kv.get("band"),
    )
    data["mode"] = kv.get("mode", "")
    data["noise_floor"] = kv.get("noise-floor", "")
    data["ccq"] = kv.get("ccq", "")
    data["modulation"] = kv.get("modulation", "")
    data["polarization"] = kv.get("polarization", "")
    data["antenna_gain"] = kv.get("antenna-gain", "")
    data["capacity"] = kv.get("capacity", "")

    # --------------------------------------------------------
    # SSH wireless monitor - preferred for runtime values
    # --------------------------------------------------------

    monitor_data, monitor_raw = mikrotik_wireless_monitor(
        client
    )
    merge_missing(data, monitor_data)

    # --------------------------------------------------------
    # Registration table - signal / CCQ fallback
    # --------------------------------------------------------

    registration = run_cmd(
        client,
        "/interface wireless registration-table print detail without-paging",
    )

    if not registration:
        registration = run_cmd(
            client,
            "/interface wifi registration-table print detail without-paging",
        )

    data["wireless_registration"] = registration

    signal_match = re.search(
        r"signal-strength\s*=\s*(-?\d+(?:\.\d+)?)",
        registration,
        re.I,
    )

    if signal_match and missing(data.get("signal_strength")):
        data["signal_strength"] = (
            signal_match.group(1) + " dBm"
        )

    ccq_match = re.search(
        r"\bccq\s*=\s*([^\s;]+)",
        registration,
        re.I,
    )

    if ccq_match and missing(data.get("ccq")):
        data["ccq"] = ccq_match.group(1)
    
    # --------------------------------------------------------
    # Device-specific SNMP fallback
    # --------------------------------------------------------
    if SNMP_ENABLED:
        try:
    # ----------------------------------------------------
    # First detect whether the device is Mimosa C5c
    # ----------------------------------------------------
    
            mimosa_detect = detect_mimosa_c5c(ip)
    
            if mimosa_detect.get("is_mimosa"):
    # ----------------------------------------------
    # Mimosa C5c -> direct SNMP
    # ----------------------------------------------
    
                snmp_radio, snmp_radio_raw = (
                    mimosa_c5c_snmp_radio(ip)
    )
    
                merge_missing(
                    data,
                snmp_radio,
    )
    
            else:
    # ----------------------------------------------
    # MikroTik -> existing SSH/RouterOS discovery
    # ----------------------------------------------
    
                snmp_radio, snmp_radio_raw = (
                    mikrotik_snmp_radio(
                    client,
                    ip,
    )
    )
    
                merge_missing(
                    data,
                snmp_radio,
    )
    
        except Exception:
                snmp_radio = {}
                snmp_radio_raw = {}
    
    # --------------------------------------------------------
    # Other RouterOS data
    # --------------------------------------------------------
    
    interfaces = run_cmd(
                    client,
    "/interface print detail without-paging",
    )
    
    routes = run_cmd(
                    client,
    "/ip route print detail without-paging",
    )
    
    bridges = run_cmd(
                    client,
    "/interface bridge print detail without-paging",
    )
    
    pppoe = run_cmd(
                    client,
    "/interface pppoe-client print detail without-paging",
    )
    
    l2tp = run_cmd(
                    client,
    "/interface l2tp-client print detail without-paging",
    )
    
    sstp = run_cmd(
                    client,
    "/interface sstp-client print detail without-paging",
    )
    
    ovpn = run_cmd(
                    client,
    "/interface ovpn-client print detail without-paging",
    )
    
    data["interfaces"] = interfaces
    data["ip_routes"] = routes
    data["bridges"] = bridges
    data["pppoe_vpn"] = (
    pppoe + "\n" + l2tp + "\n" + sstp + "\n" + ovpn
    ).strip()
    
    data["receive_power"] = data.get(
    "receive_power",
    "",
    )
    
    data["serial_number"] = first_nonempty(
    first_value(
    resource,
    "serial-number",
    "serial",
    ),
    data.get("mac_address"),
    )
    
    data["scan_status"] = "success"
    
    # --------------------------------------------------------
    # Build Raw Data without changing DB schema
    # --------------------------------------------------------
    
    raw = {
    "identity": identity,
    "resource": resource,
    "wireless": wireless,
    "wifi": wifi,
    "wireless_monitor": monitor_raw,
    "registration": registration,
    "snmp_radio": snmp_radio_raw,
    "source_priority": "ssh -> wireless-monitor -> registration -> snmp",
    }
    
    data["raw_data"] = json.dumps(
    raw,
    ensure_ascii=False,
    )
    
    return data


# ============================================================
# Cisco
# ============================================================


def cisco_info(ip, client):
    data = {
        "ip_address": ip,
        "device_type": "Cisco",
        "vendor": "Cisco",
    }

    version = run_cmd(
        client,
        "show version",
    )

    hostname = run_cmd(
        client,
        "show running-config | include ^hostname",
    )

    hostname_match = re.search(
        r"^([\w\.-]+)\s+uptime",
        version,
        re.M,
    )

    data["hostname"] = first_nonempty(
        first_value(hostname, "hostname"),
        hostname_match.group(1) if hostname_match else "",
    )

    data["firmware_version"] = first_value(
        version,
        "Version",
    )

    model_match = re.search(
        r"[Cc]isco\s+([\w/-]+)",
        version,
    )

    data["model"] = (
        model_match.group(1)
        if model_match
        else ""
    )

    data["uptime"] = first_value(
        version,
        "uptime is",
    )

    int_brief = run_cmd(
        client,
        "show ip interface brief",
    )

    int_description = run_cmd(
        client,
        "show interfaces description",
    )

    mac = run_cmd(
        client,
        "show interfaces",
    )

    data["interfaces"] = (
        int_brief + "\n" + int_description
    )

    data["raw_data"] = json.dumps(
        {
            "version": version[:4000],
            "interfaces": int_brief[:4000],
            "descriptions": int_description[:3000],
        },
        ensure_ascii=False,
    )

    mac_match = re.search(
        r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})",
        mac,
        re.I,
    )

    data["mac_address"] = normalize_mac(
        mac_match.group(1)
        if mac_match
        else ""
    )

    data["scan_status"] = "success"
    return data


# ============================================================
# Racom
# ============================================================


def racom_info(ip, client):
    data = {
        "ip_address": ip,
        "device_type": "Racom",
        "vendor": "Racom",
    }

    sys_info = (
        run_cmd(client, "show system")
        or run_cmd(client, "system info")
    )

    radio = (
        run_cmd(client, "show radio")
        or run_cmd(client, "radio info")
    )

    signal = (
        run_cmd(client, "show signal")
        or run_cmd(client, "radio signal")
    )

    data["hostname"] = first_value(
        sys_info,
        "Hostname",
        "Name",
    )

    data["model"] = first_value(
        sys_info,
        "Model",
        "Type",
    )

    data["firmware_version"] = first_value(
        sys_info,
        "Firmware",
        "SW version",
        "Version",
    )

    data["uptime"] = first_value(
        sys_info,
        "Uptime",
    )

    data["frequency"] = first_value(
        radio,
        "Frequency",
        "Rx frequency",
        "Tx frequency",
    )

    data["tx_power"] = first_value(
        radio,
        "Tx power",
        "Power",
        "Output power",
    )

    data["bandwidth"] = first_value(
        radio,
        "Bandwidth",
        "Channel bandwidth",
    )

    data["mode"] = first_value(
        radio,
        "Mode",
        "Radio mode",
    )

    data["ssid"] = first_value(
        radio,
        "SSID",
        "Network ID",
    )

    data["mac_address"] = normalize_mac(
        first_value(
            radio,
            "MAC",
            "MAC address",
        )
    )

    signal_match = re.search(
        r"-?\d+(?:\.\d+)?\s*dBm",
        signal,
        re.I,
    )

    data["signal_strength"] = (
        signal_match.group(0)
        if signal_match
        else ""
    )

    data["raw_data"] = json.dumps(
        {
            "system": sys_info[:3000],
            "radio": radio[:3000],
            "signal": signal[:1500],
        },
        ensure_ascii=False,
    )

    data["scan_status"] = "success"
    return data


# ============================================================
# Device Detection
# ============================================================


def detect(client):
    output = run_cmd(
        client,
        "/system identity print",
    )
    if output and (
        "name:" in output.lower()
        or "routeros" in output.lower()
    ):
        return "mikrotik"

    output = run_cmd(
        client,
        "show version",
    )
    if output and (
        "cisco" in output.lower()
        or "ios" in output.lower()
        or "nx-os" in output.lower()
    ):
        return "cisco"

    output = run_cmd(
        client,
        "show system",
    )
    if output and (
        "racom" in output.lower()
        or "ripex" in output.lower()
    ):
        return "racom"

    return "unknown"


def detect_from_snmp(sys_descr, sys_object_id=""):
    text = (
        safe_text(sys_descr) + " " + safe_text(sys_object_id)
    ).lower()

    if "mikrotik" in text or "routeros" in text:
        return "mikrotik"

    if "cisco" in text or "ios" in text or "nx-os" in text:
        return "cisco"

    if "racom" in text or "ripex" in text:
        return "racom"

    return "unknown"


# ============================================================
# Generic SNMP Enrichment
# ============================================================


def snmp_enrich(data, ip):
    if not SNMP_ENABLED:
        return data, {}

    standard_data, standard_raw, standard_result = (
        snmp_standard_info(ip)
    )

    merge_missing(data, standard_data)

    raw = {
        "standard": standard_raw,
        "credential_id": standard_result.get("credential_id"),
    }

    # Prefer a MAC from SNMP only if SSH didn't already provide it.
    if missing(data.get("mac_address")):
        data["mac_address"] = normalize_mac(
            standard_data.get("mac_address", "")
        )

    return data, raw


# ============================================================
# SNMP-only Device
# ============================================================

def snmp_only_info(ip):
    if not SNMP_ENABLED:
        raise RuntimeError("SNMP disabled")

    # --------------------------------------------------------
    # First get standard SNMP identification
    # --------------------------------------------------------

    standard_data, standard_raw, standard_result = (
        snmp_standard_info(ip)
    )

    if not standard_result.get("values"):
        raise RuntimeError("SNMP unavailable")

    values = standard_result.get("values", {})

    sys_descr = safe_text(
        values.get(
            SNMP_OIDS["sysDescr"],
            "",
        )
    )

    sys_object_id = safe_text(
        values.get(
            SNMP_OIDS["sysObjectID"],
            "",
        )
    )

    # --------------------------------------------------------
    # Detect device
    # --------------------------------------------------------

    mimosa_detect = detect_mimosa_c5c(ip)

    if mimosa_detect.get("is_mimosa"):
        # ----------------------------------------------------
        # Mimosa C5c
        # ----------------------------------------------------

        mimosa_data, mimosa_raw = (
            mimosa_c5c_snmp_radio(ip)
        )

        if not mimosa_data:
            raise RuntimeError(
                "Mimosa C5c SNMP unavailable"
            )

        data = {
            "ip_address": ip,
            "device_type": "Mimosa C5c",
            "vendor": "Mimosa",
            "model": "C5c",
            "scan_status": "success",
        }

        # Standard SNMP information
        merge_missing(
            data,
            standard_data,
        )

        # Mimosa-specific information
        merge_missing(
            data,
            mimosa_data,
        )

        # ----------------------------------------------------
        # Mimosa values have priority over generic SNMP values
        # ----------------------------------------------------

        for field in (
            "hostname",
            "firmware_version",
            "serial_number",
            "mac_address",
            "ssid",
            "frequency",
            "bandwidth",
            "mode",
            "tx_power",
            "rx_power",
            "receive_power",
            "signal_strength",
            "noise_floor",
            "snr",
        ):
            if not missing(mimosa_data.get(field)):
                data[field] = mimosa_data[field]

        if not missing(data.get("mac_address")):
            data["mac_address"] = normalize_mac(
                data["mac_address"]
            )
        if not missing(data.get("mac_address")):
            data["mac_address"] = normalize_mac(
                data["mac_address"]
            )

        data["raw_data"] = json.dumps(
            {
                "snmp": standard_raw,
                "mimosa": mimosa_raw,
                "mode": "mimosa-c5c-snmp",
                "sys_descr": sys_descr,
                "sys_object_id": sys_object_id,
            },
            ensure_ascii=False,
        )

        return (
            data,
            f"snmp:{standard_result.get('credential_id', 'unknown')}",
        )

    # --------------------------------------------------------
    # Existing devices
    # --------------------------------------------------------

    device_type = detect_from_snmp(
        sys_descr,
        sys_object_id,
    )

    data = {
        "ip_address": ip,
        "device_type": (
            "MikroTik"
            if device_type == "mikrotik"
            else "Cisco"
            if device_type == "cisco"
            else "Racom"
            if device_type == "racom"
            else "Unknown"
        ),
        "vendor": (
            "MikroTik"
            if device_type == "mikrotik"
            else "Cisco"
            if device_type == "cisco"
            else "Racom"
            if device_type == "racom"
            else ""
        ),
        "scan_status": "success",
    }

    merge_missing(
        data,
        standard_data,
    )

    if not missing(data.get("mac_address")):
        data["mac_address"] = normalize_mac(
            data["mac_address"]
        )

    data["raw_data"] = json.dumps(
        {
            "snmp": standard_raw,
            "mode": "snmp-only",
        },
        ensure_ascii=False,
    )

    return (
        data,
        f"snmp:{standard_result.get('credential_id', 'unknown')}",
    )

# ============================================================
# Single IP Scan
# ============================================================


def scan_single_ip(ip):
    if is_blacklisted(ip):
        return (
            "skipped",
            ip,
            None,
        )

    if not host_is_alive(ip):
        return (
            "not_alive",
            ip,
            None,
        )

    client = None
    credential_id = ""
    ssh_error = ""
    snmp_raw = {}

    # --------------------------------------------------------
    # 1) Try SSH first
    # --------------------------------------------------------

    try:
        client, credential_id = ssh_connect(ip)

        device_type = detect(client)

        if device_type == "mikrotik":
            data = routeros_info(
                ip,
                client,
            )
        elif device_type == "cisco":
            data = cisco_info(
                ip,
                client,
            )
        elif device_type == "racom":
            data = racom_info(
                ip,
                client,
            )
        else:
            data = {
                "ip_address": ip,
                "device_type": "Unknown",
                "scan_status": "unknown_type",
            }

        data["credential_id"] = credential_id

        # ----------------------------------------------------
        # 2) SNMP enrichment
        # ----------------------------------------------------

        if SNMP_ENABLED:
            try:
                data, snmp_raw = snmp_enrich(
                    data,
                    ip,
                )
            except Exception as e:
                snmp_raw = {
                    "error": str(e)[:180],
                }

        # Keep existing raw_data and add source information
        try:
            existing_raw = json.loads(
                data.get("raw_data", "{}")
            )
            if not isinstance(existing_raw, dict):
                existing_raw = {
                    "ssh_raw": data.get(
                        "raw_data", ""
                    )
                }
        except Exception:
            existing_raw = {
                "ssh_raw": data.get(
                    "raw_data", ""
                )
            }

        existing_raw["snmp_generic"] = snmp_raw
        existing_raw["data_merge"] = (
            "SSH first; SNMP fills only missing fields"
        )

        data["raw_data"] = json.dumps(
            existing_raw,
            ensure_ascii=False,
        )

        row = upsert_device(data)

        return (
            "success",
            ip,
            dict(row) if row else data,
        )

    except Exception as e:
        ssh_error = str(e)[:200]

    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    # --------------------------------------------------------
    # 3) SSH failed -> try SNMP-only
    # --------------------------------------------------------

    if SNMP_ENABLED:
        try:
            data, snmp_credential_id = snmp_only_info(ip)
            data["credential_id"] = snmp_credential_id

            # Preserve a small SSH error in raw_data, not password.
            try:
                raw = json.loads(
                    data.get("raw_data", "{}")
                )
                if not isinstance(raw, dict):
                    raw = {}
            except Exception:
                raw = {}

            raw["ssh_fallback_error"] = ssh_error
            raw["data_merge"] = "SNMP-only fallback"

            data["raw_data"] = json.dumps(
                raw,
                ensure_ascii=False,
            )

            row = upsert_device(data)

            return (
                "success",
                ip,
                dict(row) if row else data,
            )

        except Exception as snmp_error:
            error_text = (
                "SSH: " + ssh_error
                + " | SNMP: "
                + str(snmp_error)[:150]
            )[:200]
    else:
        error_text = ssh_error[:200]

    try:
        upsert_device({
            "ip_address": ip,
            "device_type": "",
            "scan_status": "ssh_failed: " + error_text,
        })
    except Exception:
        pass

    return (
        "failed",
        ip,
        {
            "error": error_text,
        },
    )


# ============================================================
# Full Scan
# ============================================================


def run_scan(target_ips=None):
    init_db()
    start = time.time()

    all_ips = (
        target_ips
        or get_all_ips()
    )

    all_ips = [
        ip
        for ip in all_ips
        if not is_blacklisted(ip)
    ]

    alive = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(
            100,
            len(all_ips) or 1,
        )
    ) as executor:
        futures = {
            executor.submit(
                host_is_alive,
                ip,
            ): ip
            for ip in all_ips
        }

        for future in concurrent.futures.as_completed(
            futures
        ):
            ip = futures[future]
            try:
                if (
                    future.result()
                    and not is_blacklisted(ip)
                ):
                    alive.append(ip)
            except Exception:
                pass

    snapshots = []
    success = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(
            1,
            SCAN_WORKERS,
        )
    ) as executor:
        futures = {
            executor.submit(
                scan_single_ip,
                ip,
            ): ip
            for ip in alive
        }

        for future in concurrent.futures.as_completed(
            futures
        ):
            try:
                status, ip, snapshot = future.result()
            except Exception as e:
                ip = futures[future]
                status = "failed"
                snapshot = {
                    "error": str(e)[:200],
                }

            if status == "success":
                success += 1
            elif status == "failed":
                failed += 1

            snapshots.append(
                (
                    ip,
                    status,
                    snapshot or {},
                )
            )

    duration = time.time() - start

    scan_id = log_scan(
        len(all_ips),
        len(alive),
        success,
        failed,
        duration,
        snapshots,
    )

    return {
        "scan_id": scan_id,
        "total_ips": len(all_ips),
        "found": len(alive),
        "success": success,
        "failed": failed,
        "duration": duration,
    }


# ============================================================
# Main
# ============================================================


if __name__ == "__main__":
    print("=" * 60)
    print("Wireless Monitor Scanner - SSH + SNMP")
    print("=" * 60)
    print("Network:", NETWORK)
    print("SSH Port:", SSH_PORT)
    print("SSH Timeout:", SSH_TIMEOUT)
    print("Workers:", SCAN_WORKERS)
    print(
        "Credentials:",
        [
            {
                "username": c.get("username"),
                "id": c.get("id"),
            }
            for c in CREDENTIALS
        ],
    )
    print(
        "Legacy SSH:",
        "enabled" if LEGACY_SSH_FALLBACK else "disabled",
    )
    print(
        "OpenSSH:",
        shutil.which("ssh") or "NOT FOUND",
    )
    print(
        "sshpass:",
        shutil.which("sshpass") or "NOT FOUND",
    )
    print("SNMP:", "enabled" if SNMP_ENABLED else "disabled")
    print("SNMP Version:", SNMP_VERSION)
    print("SNMP Port:", SNMP_PORT)
    print(
        "SNMP Communities:",
        [
            {
                "id": x.get("id"),
            }
            for x in SNMP_CREDENTIALS
        ],
    )
    print("PySNMP:", "available" if SnmpDispatcher else "NOT INSTALLED")
    print("=" * 60)
    print(run_scan())
