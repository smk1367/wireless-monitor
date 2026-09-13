#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import time

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
# Logging
# ============================================================

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


# ============================================================
# Configuration
# ============================================================

NETWORK = os.getenv("SCAN_NETWORK", "172.17.240.0/20")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "10"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "40"))

LEGACY_SSH_FALLBACK = os.getenv("LEGACY_SSH_FALLBACK", "1").strip().lower() in {
    "1", "true", "yes", "on"
}

SNMP_ENABLED = os.getenv("SNMP_ENABLED", "1").strip().lower() in {
    "1", "true", "yes", "on"
}

SNMP_PORT = int(os.getenv("SNMP_PORT", "161"))

SNMP_VERSION = os.getenv(
    "SNMP_VERSION",
    "2c",
).strip().lower()

SNMP_TIMEOUT = float(
    os.getenv(
        "SNMP_TIMEOUT",
        "3",
    )
)

SNMP_RETRIES = int(
    os.getenv(
        "SNMP_RETRIES",
        "2",
    )
)

# فقط community خودمان
SNMP_COMMUNITY = (
    os.getenv("SNMP_COMMUNITY")
    or "ngstehwl"
).strip()


def _snmp_credentials():
    return [
        {
            "community": SNMP_COMMUNITY,
            "id": "ngstehwl",
        }
    ]


SNMP_CREDENTIALS = _snmp_credentials()

# ============================================================
# Generic helpers
# ============================================================

def safe_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").strip()
    return str(value).strip()


def missing(value):
    if value is None:
        return True
    text = safe_text(value)
    return text.lower() in {
        "", "-", "--", "n/a", "unknown", "none", "null"
    }


def first_nonempty(*values):
    for value in values:
        if not missing(value):
            return safe_text(value)
    return ""


def normalize_number_unit(value, default_unit=""):
    text = safe_text(value)
    if not text:
        return ""
    if default_unit and re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return f"{text} {default_unit}"
    return text


def normalize_dbm(value):
    text = safe_text(value)
    if not text:
        return ""
    text = re.sub(r"\s*dBm\s*$", "", text, flags=re.I).strip()
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        return f"{text} dBm"
    return safe_text(value)


def parse_key_values(text):
    """Parse RouterOS key=value / key: value output safely."""
    out = {}
    if not text:
        return out

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # key="quoted value"
        for match in re.finditer(
            r"([A-Za-z][A-Za-z0-9_.-]*)\s*(?:=|:)\s*"
            r"(?:\"([^\"]*)\"|'([^']*)'|([^\s;]+))",
            line,
        ):
            key = match.group(1).lower()
            value = next(
                x for x in (
                    match.group(2),
                    match.group(3),
                    match.group(4),
                ) if x is not None
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

    if re.fullmatch(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value):
        return value.upper()

    if re.fullmatch(r"[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}", value):
        raw = value.replace(".", "")
        return ":".join(raw[i:i + 2].upper() for i in range(0, 12, 2))

    hex_pairs = re.findall(r"[0-9A-Fa-f]{2}", value)
    if len(hex_pairs) == 6:
        return ":".join(x.upper() for x in hex_pairs)

    return value


def merge_missing(data, extra):
    """Only fill blank fields. Useful for general enrichment."""
    for key, value in (extra or {}).items():
        if key.startswith("_"):
            continue
        if not missing(value) and missing(data.get(key)):
            data[key] = value
    return data


def merge_runtime(data, runtime, fields):
    """Runtime wireless values must replace stale/static values."""
    for field in fields:
        value = runtime.get(field)
        if not missing(value):
            data[field] = value
    return data


def channel_parts(channel):
    """5855/20-Ceee/ac -> (5855, 20 MHz)."""
    channel = safe_text(channel)
    if not channel:
        return "", ""

    match = re.match(
        r"^\s*(\d+(?:\.\d+)?)"
        r"(?:/(\d+(?:\.\d+)?))?",
        channel,
    )
    if not match:
        return "", ""

    frequency = match.group(1)
    bandwidth = (
        f"{match.group(2)} MHz"
        if match.group(2)
        else ""
    )
    return frequency, bandwidth


# ============================================================
# Credentials
# ============================================================

def _credentials():
    out = []

    raw = os.getenv("SSH_CREDENTIALS_JSON", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    username = safe_text(item.get("username"))
                    password = safe_text(item.get("password"))
                    if username:
                        out.append({
                            "username": username,
                            "password": password,
                            "id": item.get("id", f"json-{len(out) + 1}"),
                        })
        except Exception as exc:
            logger.warning("Invalid SSH_CREDENTIALS_JSON: %s", exc)

    for i in range(1, 11):
        username = os.getenv(f"SSH_USER_{i}", "").strip()
        password = os.getenv(f"SSH_PASS_{i}", "")
        if username:
            out.append({
                "username": username,
                "password": password,
                "id": f"cred-{i}",
            })

    username = os.getenv("SSH_USER", "").strip()
    password = os.getenv("SSH_PASS", "")
    if username:
        out.append({
            "username": username,
            "password": password,
            "id": "default",
        })

    uniq = []
    seen = set()
    for item in out:
        key = (item["username"], item["password"])
        if key not in seen:
            uniq.append(item)
            seen.add(key)
    return uniq


CREDENTIALS = _credentials()


def _snmp_credentials():
    out = []

    raw = os.getenv("SNMP_COMMUNITIES_JSON", "").strip()
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
                                "id": f"json-{len(out) + 1}",
                            })
                    elif isinstance(item, dict):
                        community = safe_text(item.get("community"))
                        if community:
                            out.append({
                                "community": community,
                                "id": item.get("id", f"json-{len(out) + 1}"),
                            })
        except Exception as exc:
            logger.warning("Invalid SNMP_COMMUNITIES_JSON: %s", exc)

    if SNMP_COMMUNITY.strip():
        out.append({
            "community": SNMP_COMMUNITY.strip(),
            "id": "default",
        })

    uniq = []
    seen = set()
    for item in out:
        if item["community"] not in seen:
            uniq.append(item)
            seen.add(item["community"])
    return uniq


SNMP_CREDENTIALS = _snmp_credentials()


# ============================================================
# Host discovery
# ============================================================

def get_all_ips():
    network = ipaddress.ip_network(NETWORK, strict=False)
    ips = [
        str(ip)
        for ip in network.hosts()
        if not is_blacklisted(str(ip))
    ]

    for row in list_manual_ips():
        ip = row["ip_address"]
        if row["enabled"] and not is_blacklisted(ip) and ip not in ips:
            ips.append(ip)

    return ips


def port_is_open(ip, port, timeout=1):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def host_is_alive(ip):
    if port_is_open(ip, SSH_PORT, timeout=1):
        return True

    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


# ============================================================
# SSH clients
# ============================================================

class _LegacyOutput:
    def __init__(self, text):
        self.text = text if isinstance(text, str) else str(text or "")

    def read(self):
        return self.text.encode("utf-8", "replace")


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

        command_line = [
            "sshpass", "-e", "ssh", *ssh_options,
            f"{self.username}@{self.ip}", command,
        ]

        try:
            result = subprocess.run(
                command_line,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=max(timeout, SSH_TIMEOUT) + 5,
            )
            return None, _LegacyOutput(result.stdout), _LegacyOutput(result.stderr)
        except subprocess.TimeoutExpired as exc:
            return None, _LegacyOutput(exc.stdout or ""), _LegacyOutput(exc.stderr or "")
        except Exception:
            return None, _LegacyOutput(""), _LegacyOutput("")

    def close(self):
        return None


def legacy_ssh_available():
    return (
        LEGACY_SSH_FALLBACK
        and shutil.which("ssh") is not None
        and shutil.which("sshpass") is not None
    )


def ssh_connect_normal(ip, credential):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
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
        raise RuntimeError("Legacy SSH unavailable: ssh/sshpass not installed")

    client = LegacySSHClient(ip, credential["username"], credential["password"])
    _, stdout, stderr = client.exec_command(
        "/system identity print",
        timeout=SSH_TIMEOUT,
    )
    output = stdout.read().decode("utf-8", "replace").strip()
    error_output = stderr.read().decode("utf-8", "replace").strip()

    if not output:
        raise RuntimeError(
            "Legacy SSH failed"
            + (f": {error_output[:180]}" if error_output else "")
        )

    return client


def ssh_connect(ip):
    if not CREDENTIALS:
        raise ValueError("No SSH credentials configured")

    last_error = None

    for credential in CREDENTIALS:
        try:
            return (
                ssh_connect_normal(ip, credential),
                f"normal:{credential.get('id', credential['username'])}",
            )
        except Exception as exc:
            last_error = exc

        if LEGACY_SSH_FALLBACK:
            try:
                return (
                    ssh_connect_legacy(ip, credential),
                    f"legacy:{credential.get('id', credential['username'])}",
                )
            except Exception as exc:
                last_error = exc

    raise last_error or RuntimeError("SSH connection failed")


def run_cmd(client, command, timeout=8):
    try:
        _, stdout, _ = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", "replace").strip()
    except Exception:
        return ""


# ============================================================
# SNMP helpers
# ============================================================

async def _snmp_get_async(ip, community, oids, version="2c"):
    if not SNMP_ENABLED or SnmpDispatcher is None:
        return {}

    results = {}
    mp_model = 0 if str(version).lower() in {"1", "v1"} else 1

    dispatcher = SnmpDispatcher()
    try:
        target = await UdpTransportTarget.create(
            (ip, SNMP_PORT),
            timeout=SNMP_TIMEOUT,
            retries=SNMP_RETRIES,
        )

        result = await get_cmd(
            dispatcher,
            CommunityData(community, mpModel=mp_model),
            target,
            *[(oid, None) for oid in oids],
        )

        error_indication, error_status, error_index, var_binds = result

        if error_indication or error_status:
            return {}

        for oid, value in var_binds:
            results[safe_text(oid)] = safe_text(
                value.prettyPrint() if hasattr(value, "prettyPrint") else value
            )

        return results
    finally:
        try:
            dispatcher.close_dispatcher()
        except Exception:
            try:
                dispatcher.transport_dispatcher.close_dispatcher()
            except Exception:
                pass


def snmp_get(ip, oids, credentials=None):
    if not SNMP_ENABLED:
        return {"values": {}, "credential_id": "", "community": ""}

    if SnmpDispatcher is None:
        return {
            "values": {},
            "credential_id": "",
            "community": "",
            "error": "pysnmp not installed",
        }

    credentials = credentials or SNMP_CREDENTIALS

    for credential in credentials:
        try:
            values = asyncio.run(
                _snmp_get_async(
                    ip,
                    credential["community"],
                    oids,
                    version=SNMP_VERSION,
                )
            )
            if values:
                return {
                    "values": values,
                    "credential_id": credential.get("id", "snmp"),
                    "community": credential["community"],
                }
        except Exception as exc:
            logger.debug("SNMP %s failed: %s", ip, exc)

    return {"values": {}, "credential_id": "", "community": ""}


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
    result = snmp_get(ip, list(SNMP_OIDS.values()))
    values = result.get("values", {})
    reverse = {oid: name for name, oid in SNMP_OIDS.items()}
    by_name = {reverse.get(oid, oid): value for oid, value in values.items()}

    data = {
        "hostname": first_nonempty(by_name.get("sysName")),
        "firmware_version": first_nonempty(by_name.get("sysDescr")),
        "uptime": first_nonempty(by_name.get("sysUpTime")),
        "mac_address": normalize_mac(by_name.get("ifPhysAddress.1")),
    }

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
    "tx_phy_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.2.1",
    "tx_phy_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.2.2",
    "tx_mcs_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.3.1",
    "tx_mcs_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.3.2",
    "rx_phy_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.5.1",
    "rx_phy_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.5.2",
    "rx_mcs_1": "1.3.6.1.4.1.43356.2.1.2.6.2.1.6.1",
    "rx_mcs_2": "1.3.6.1.4.1.43356.2.1.2.6.2.1.6.2",
    "channel_width": "1.3.6.1.4.1.43356.2.1.2.6.3.1.3.1",
    "channel_tx_power": "1.3.6.1.4.1.43356.2.1.2.6.3.1.4.1",
    "channel_frequency": "1.3.6.1.4.1.43356.2.1.2.6.3.1.5.1",
    "phy_tx_rate": "1.3.6.1.4.1.43356.2.1.2.7.1.0",
    "phy_rx_rate": "1.3.6.1.4.1.43356.2.1.2.7.2.0",
    "per_tx": "1.3.6.1.4.1.43356.2.1.2.7.3.0",
    "per_rx": "1.3.6.1.4.1.43356.2.1.2.7.4.0",
}


def _num(value):
    if missing(value):
        return None
    text = safe_text(value).replace("INTEGER:", "").strip()
    try:
        return float(text) if "." in text else int(text)
    except (TypeError, ValueError):
        return None


def _scaled(value, divisor=10):
    num = _num(value)
    return None if num is None else num / divisor


def _fmt(value, unit=None, divisor=None):
    if missing(value):
        return None
    num = _scaled(value, divisor) if divisor is not None else _num(value)
    if num is None:
        return safe_text(value)
    text = str(int(num)) if float(num).is_integer() else f"{num:.1f}"
    return f"{text} {unit}" if unit else text


def _avg(v1, v2, divisor=10):
    vals = [_num(v) for v in (v1, v2)]
    vals = [v for v in vals if v is not None]
    return None if not vals else sum(vals) / len(vals) / divisor


def mimosa_c5c_snmp_radio(ip):
    result = snmp_get(ip, list(MIMOSA_C5C_OIDS.values()))
    values = result.get("values", {})
    if not values:
        return {}, {"snmp": result, "queried_oids": MIMOSA_C5C_OIDS}

    def get(name):
        oid = MIMOSA_C5C_OIDS[name]
        return values.get(oid)

    data = {"model": "C5c", "vendor": "Mimosa"}

    mapping = {
        "device_name": "hostname",
        "serial_number": "serial_number",
        "firmware": "firmware_version",
        "ssid": "ssid",
        "local_ip": "device_ip",
        "wireless_mode": "mode",
    }
    for source, target in mapping.items():
        value = get(source)
        if not missing(value):
            data[target] = safe_text(value)

    if not missing(get("wan_mac")):
        data["mac_address"] = normalize_mac(get("wan_mac"))

    temp = _num(get("temperature"))
    if temp is not None:
        data["temperature"] = f"{temp / 10:.1f} C"

    tx1, tx2 = get("tx_power_1"), get("tx_power_2")
    rx1, rx2 = get("rx_power_1"), get("rx_power_2")
    noise1, noise2 = get("rx_noise_1"), get("rx_noise_2")
    snr1, snr2 = get("snr_1"), get("snr_2")

    if not missing(tx1):
        data["tx_power_chain1"] = _fmt(tx1, "dBm", 10)
    if not missing(tx2):
        data["tx_power_chain2"] = _fmt(tx2, "dBm", 10)
    if not missing(rx1):
        data["receive_power_chain1"] = _fmt(rx1, "dBm", 10)
    if not missing(rx2):
        data["receive_power_chain2"] = _fmt(rx2, "dBm", 10)

    avg_tx = _avg(tx1, tx2)
    avg_rx = _avg(rx1, rx2)
    avg_noise = _avg(noise1, noise2)
    avg_snr = _avg(snr1, snr2)

    if avg_tx is not None:
        data["tx_power"] = f"{avg_tx:.1f} dBm"
    if avg_rx is not None:
        data["rx_power"] = f"{avg_rx:.1f} dBm"
        data["receive_power"] = f"{avg_rx:.1f} dBm"
        data["signal_strength"] = f"{avg_rx:.1f} dBm"
    if avg_noise is not None:
        data["noise_floor"] = f"{avg_noise:.1f} dBm"
    if avg_snr is not None:
        data["snr"] = f"{avg_snr:.1f} dB"

    frequency = get("channel_frequency") or get("frequency_1")
    if not missing(frequency):
        data["frequency"] = _fmt(frequency, "MHz")

    width = get("channel_width")
    if not missing(width):
        data["bandwidth"] = _fmt(width, "MHz")

    raw = {
        "device_type": "mimosa_c5c",
        "queried_oids": MIMOSA_C5C_OIDS,
        "snmp": result,
    }
    return data, raw


def detect_mimosa_c5c(ip):
    result = snmp_get(ip, [SNMP_OIDS["sysDescr"], SNMP_OIDS["sysObjectID"]])
    values = result.get("values", {})
    descr = safe_text(values.get(SNMP_OIDS["sysDescr"])).lower()
    object_id = safe_text(values.get(SNMP_OIDS["sysObjectID"])).lower()
    return {
        "is_mimosa": "airspan-c5c" in descr or "mimosa" in descr or "1.3.6.1.4.1.43356" in object_id,
        "sys_descr": descr,
        "sys_object_id": object_id,
        "result": result,
    }


# ============================================================
# MikroTik temporary RF simulation
# ============================================================
# Used ONLY when MikroTik does not expose a scalar TX/RX value.
# Values are generated per device and kept stable across scans so the
# dashboard does not show one identical number for every MikroTik.
# They are explicitly marked as simulated in raw_data.
MIKROTIK_PLACEHOLDER_ENABLED = os.getenv(
    "MIKROTIK_PLACEHOLDER_ENABLED",
    "1",
).strip().lower() in {"1", "true", "yes", "on"}


def _simulated_rf_values(ip, signal=None):
    """Generate plausible temporary RF values per MikroTik device.

    TX: 18..30 dBm.
    RX: follows the measured signal when available, with a small
        device-specific offset; otherwise -25..-50 dBm.

    These values are NOT device readings and are only a temporary UI fill.
    """
    seed = hashlib.sha256(safe_text(ip).encode("utf-8")).digest()

    tx_dbm = 18 + (seed[0] % 13)

    measured = safe_text(signal)
    match = re.search(r"(-?\d+(?:\.\d+)?)", measured)

    if match:
        try:
            base = float(match.group(1))
            offset = ((seed[1] % 7) - 3) * 0.5
            rx_dbm = max(-75.0, min(-25.0, base + offset))
        except ValueError:
            rx_dbm = -25.0 - (seed[1] % 26)
    else:
        rx_dbm = -25.0 - (seed[1] % 26)

    tx_text = f"{tx_dbm} dBm"
    rx_text = (
        f"{int(rx_dbm)} dBm"
        if float(rx_dbm).is_integer()
        else f"{rx_dbm:.1f} dBm"
    )

    return tx_text, rx_text

# ============================================================
# MikroTik wireless data
# ============================================================


def mikrotik_wireless_monitor(client):
    """
    Read live MikroTik wireless monitor values.

    RouterOS 6 wireless output is used as the primary source.
    RouterOS 7 wifi is attempted as a fallback.

    IMPORTANT:
      - signal-strength       = RX signal measured by the station / peer signal
      - tx-signal-strength    = peer TX signal seen locally
      - neither is local TX power
      - APs often do not expose peer values in `monitor`; registration-table
        is handled separately by `mikrotik_registration_clients()`.
    """
    commands = [
        "/interface wireless monitor [find] once",
        "/interface wifi monitor [find] once",
    ]

    raw = {}
    merged = {}

    for command in commands:
        output = run_cmd(client, command, timeout=8)
        if not output:
            continue

        raw[command] = output
        parsed = parse_key_values(output)

        # Prefer the first non-empty value.
        for key, value in parsed.items():
            if missing(merged.get(key)):
                merged[key] = value

        # Stop after the first useful wireless implementation.
        if merged.get("status"):
            break

    data = {}

    status = first_nonempty(
        merged.get("status"),
    )

    if status:
        data["wireless_status"] = status

    # --------------------------------------------------------
    # SSID
    # --------------------------------------------------------

    data["ssid"] = first_nonempty(
        merged.get("ssid"),
    )

    # --------------------------------------------------------
    # Channel / Frequency / Bandwidth
    # --------------------------------------------------------

    channel = first_nonempty(
        merged.get("channel"),
    )

    if channel:
        data["channel"] = channel

        freq, bw = channel_parts(channel)

        if freq:
            data["frequency"] = freq

        if bw:
            data["bandwidth"] = bw

    explicit_frequency = first_nonempty(
        merged.get("frequency"),
    )

    if explicit_frequency:
        data["frequency"] = re.sub(
            r"\s*MHz$",
            "",
            explicit_frequency,
            flags=re.I,
        ).strip()

    explicit_bandwidth = first_nonempty(
        merged.get("channel-width"),
        merged.get("bandwidth"),
        merged.get("channel-widths"),
    )

    if explicit_bandwidth:
        # Keep user-friendly dashboard value.
        bw_num = re.match(
            r"^\s*(\d+(?:\.\d+)?)",
            explicit_bandwidth,
        )
        data["bandwidth"] = (
            bw_num.group(1) + " MHz"
            if bw_num
            else explicit_bandwidth
        )

    # --------------------------------------------------------
    # Mode
    # --------------------------------------------------------

    data["mode"] = first_nonempty(
        merged.get("mode"),
    )

    # --------------------------------------------------------
    # Signal / RX Power
    # --------------------------------------------------------

    signal = first_nonempty(
        merged.get("signal-strength"),
        merged.get("signal"),
    )

    if signal:
        signal = normalize_dbm(signal)

        data["rx_power"] = signal
        data["receive_power"] = signal
        data["signal_strength"] = signal

    # Per-chain RX.
    for field, source in (
        ("signal_strength_ch0", "signal-strength-ch0"),
        ("signal_strength_ch1", "signal-strength-ch1"),
    ):
        value = first_nonempty(merged.get(source))
        if value:
            data[field] = normalize_dbm(value)

    # --------------------------------------------------------
    # Peer TX signal
    # --------------------------------------------------------

    peer_tx = first_nonempty(
        merged.get("tx-signal-strength"),
    )

    if peer_tx:
        data["peer_tx_signal"] = normalize_dbm(peer_tx)

    for field, source in (
        ("peer_tx_signal_ch0", "tx-signal-strength-ch0"),
        ("peer_tx_signal_ch1", "tx-signal-strength-ch1"),
    ):
        value = first_nonempty(merged.get(source))
        if value:
            data[field] = normalize_dbm(value)

    # --------------------------------------------------------
    # Noise / SNR
    # --------------------------------------------------------

    noise = first_nonempty(
        merged.get("noise-floor"),
    )

    if noise:
        data["noise_floor"] = normalize_dbm(noise)

    snr = first_nonempty(
        merged.get("signal-to-noise"),
    )

    if snr:
        data["snr"] = snr

    # --------------------------------------------------------
    # CCQ
    # --------------------------------------------------------

    rx_ccq = first_nonempty(
        merged.get("rx-ccq"),
    )
    tx_ccq = first_nonempty(
        merged.get("tx-ccq"),
    )

    if rx_ccq:
        data["ccq"] = rx_ccq

    elif tx_ccq:
        data["ccq"] = tx_ccq

    if rx_ccq:
        data["rx_ccq"] = rx_ccq

    if tx_ccq:
        data["tx_ccq"] = tx_ccq

    # --------------------------------------------------------
    # Rates / distance
    # --------------------------------------------------------

    data["tx_rate"] = first_nonempty(
        merged.get("tx-rate"),
    )
    data["rx_rate"] = first_nonempty(
        merged.get("rx-rate"),
    )
    data["distance"] = first_nonempty(
        merged.get("current-distance"),
    )

    # --------------------------------------------------------
    # BSSID
    # --------------------------------------------------------

    bssid = first_nonempty(
        merged.get("bssid"),
        merged.get("mac-address"),
    )

    if bssid:
        data["mac_address"] = normalize_mac(bssid)

    data["wds_link"] = first_nonempty(
        merged.get("wds-link"),
    )
    data["bridge"] = first_nonempty(
        merged.get("bridge"),
    )

    # --------------------------------------------------------
    # LOCAL TX POWER
    # --------------------------------------------------------
    #
    # Do NOT use current-tx-powers. On RouterOS 6 this may be a
    # rate table such as:
    #
    # 6Mbps:31(25/31),9Mbps:31(25/31),...
    #
    # That is not a single TX power value suitable for the dashboard.
    # Only accept explicit scalar values.

    for key in (
        "current-tx-power",
        "tx-power-real",
        "tx-power",
        "output-power",
    ):
        value = first_nonempty(merged.get(key))

        if not value:
            continue

        # Reject rate-table strings.
        if re.search(r"\d+\s*Mbps\s*:", value, re.I):
            continue

        data["tx_power"] = value
        break

    return (
        {k: v for k, v in data.items() if not missing(v)},
        raw,
    )


def mikrotik_wireless_interface(client):
    """
    Read interface configuration.

    TX power mode is configuration data; it is separate from TX power.
    """
    commands = [
        "/interface wireless print detail without-paging",
        "/interface wifi print detail without-paging",
    ]

    raw = {}
    merged = {}

    for command in commands:
        output = run_cmd(client, command, timeout=8)
        if not output:
            continue

        raw[command] = output
        parsed = parse_key_values(output)

        for key, value in parsed.items():
            if missing(merged.get(key)):
                merged[key] = value

        if merged.get("name"):
            break

    data = {}

    data["interface_name"] = first_nonempty(
        merged.get("name"),
    )

    data["mode"] = first_nonempty(
        merged.get("mode"),
    )

    data["tx_power_mode"] = first_nonempty(
        merged.get("tx-power-mode"),
    )

    # Only scalar local TX power.
    tx_power = first_nonempty(
        merged.get("tx-power"),
        merged.get("output-power"),
        merged.get("current-tx-power"),
        merged.get("tx-power-real"),
    )

    if tx_power and not re.search(
        r"\d+\s*Mbps\s*:",
        tx_power,
        re.I,
    ):
        data["tx_power"] = tx_power

    data["antenna_gain"] = first_nonempty(
        merged.get("antenna-gain"),
    )
    data["polarization"] = first_nonempty(
        merged.get("polarization"),
    )

    return (
        {k: v for k, v in data.items() if not missing(v)},
        raw,
    )


def _split_registration_records(text):
    """
    Best-effort split of RouterOS registration-table output.

    RouterOS may print one or many records separated by blank lines.
    """
    if not text:
        return []

    blocks = re.split(
        r"\n\s*\n+",
        text.strip(),
    )

    return [
        block.strip()
        for block in blocks
        if block.strip()
    ]


def _registration_record_data(block):
    """
    Parse one registration-table record.

    Supports both:
      key=value
      key: value
    """
    parsed = parse_key_values(block)

    # Some RouterOS outputs may use a leading number/id line.
    if not parsed:
        return {}

    result = {}

    for key in (
        "interface",
        "mac-address",
        "mac",
        "ap",
        "interface",
        "signal-strength",
        "signal-strength-ch0",
        "signal-strength-ch1",
        "tx-signal-strength",
        "tx-signal-strength-ch0",
        "tx-signal-strength-ch1",
        "noise-floor",
        "signal-to-noise",
        "tx-ccq",
        "rx-ccq",
        "ccq",
        "tx-rate",
        "rx-rate",
        "uptime",
        "last-activity",
        "distance",
        "current-distance",
        "routeros-version",
        "tx-byte",
        "rx-byte",
    ):
        if key in parsed and not missing(parsed[key]):
            result[key] = parsed[key]

    return result


def mikrotik_registration_clients(client):
    """
    Parse all registration-table clients.

    Returns:
        clients: list[dict]
        raw_output: str
    """
    commands = [
        "/interface wireless registration-table print detail without-paging",
        "/interface wifi registration-table print detail without-paging",
    ]

    for command in commands:
        output = run_cmd(client, command, timeout=8)

        if not output:
            continue

        blocks = _split_registration_records(output)

        clients = []

        for block in blocks:
            item = _registration_record_data(block)

            if item:
                clients.append(item)

        # If blank-line splitting did not produce clean records,
        # still try parsing the complete output as one record.
        if not clients:
            item = _registration_record_data(output)
            if item:
                clients.append(item)

        if clients:
            return clients, output

    return [], ""


def _registration_to_runtime(client_item):
    """
    Convert a registration-table client record to dashboard runtime fields.
    """
    if not client_item:
        return {}

    data = {}

    signal = first_nonempty(
        client_item.get("signal-strength"),
    )

    if signal:
        signal = normalize_dbm(signal)
        data["signal_strength"] = signal
        data["rx_power"] = signal
        data["receive_power"] = signal

    peer_tx = first_nonempty(
        client_item.get("tx-signal-strength"),
    )

    if peer_tx:
        data["peer_tx_signal"] = normalize_dbm(peer_tx)

    for field, source in (
        ("signal_strength_ch0", "signal-strength-ch0"),
        ("signal_strength_ch1", "signal-strength-ch1"),
        ("peer_tx_signal_ch0", "tx-signal-strength-ch0"),
        ("peer_tx_signal_ch1", "tx-signal-strength-ch1"),
    ):
        value = first_nonempty(client_item.get(source))
        if value:
            data[field] = normalize_dbm(value)

    noise = first_nonempty(
        client_item.get("noise-floor"),
    )

    if noise:
        data["noise_floor"] = normalize_dbm(noise)

    snr = first_nonempty(
        client_item.get("signal-to-noise"),
    )

    if snr:
        data["snr"] = snr

    rx_ccq = first_nonempty(
        client_item.get("rx-ccq"),
    )
    tx_ccq = first_nonempty(
        client_item.get("tx-ccq"),
    )
    ccq = first_nonempty(
        client_item.get("ccq"),
    )

    if rx_ccq:
        data["ccq"] = rx_ccq
    elif tx_ccq:
        data["ccq"] = tx_ccq
    elif ccq:
        data["ccq"] = ccq

    if rx_ccq:
        data["rx_ccq"] = rx_ccq

    if tx_ccq:
        data["tx_ccq"] = tx_ccq

    tx_rate = first_nonempty(
        client_item.get("tx-rate"),
    )
    rx_rate = first_nonempty(
        client_item.get("rx-rate"),
    )

    if tx_rate:
        data["tx_rate"] = tx_rate

    if rx_rate:
        data["rx_rate"] = rx_rate

    distance = first_nonempty(
        client_item.get("current-distance"),
        client_item.get("distance"),
    )

    if distance:
        data["distance"] = distance

    mac = first_nonempty(
        client_item.get("mac-address"),
        client_item.get("mac"),
    )

    if mac:
        data["peer_mac"] = normalize_mac(mac)

    return {
        k: v
        for k, v in data.items()
        if not missing(v)
    }


def mikrotik_snmp_radio(client, ip):
    """
    Keep SNMP only as a supplementary mechanism.

    IMPORTANT: the previous code incorrectly treated
    1.3.6.1.4.1.14988.1.1.1.3.1.10 as TX power. That object is
    not local TX power and must not be used for tx_power.
    """
    # No hard-coded TX/RX OIDs here.
    # RouterOS runtime data above is authoritative for wireless metrics.
    return {}, {
        "disabled_reason": "MikroTik wireless metrics are collected from RouterOS monitor/interface output"
    }


def routeros_info(ip, client):
    """
    Collect MikroTik data with explicit AP/Station handling.

    Source priority:
      1. RouterOS wireless monitor (live radio state)
      2. RouterOS wireless interface configuration
      3. AP registration-table client data
      4. Generic SNMP identification only

    AP and Station are intentionally handled differently:
      - Station: monitor is authoritative for signal/peer TX/CCQ/noise.
      - AP: monitor supplies local radio state; registration-table supplies
        the connected peer/client metrics when available.
    """
    data = {
        "ip_address": ip,
        "device_type": "MikroTik",
        "vendor": "MikroTik",
    }

    # --------------------------------------------------------
    # Identity / system
    # --------------------------------------------------------

    identity = run_cmd(
        client,
        "/system identity print",
    )

    resource = run_cmd(
        client,
        "/system resource print",
    )

    health = run_cmd(
        client,
        "/system health print",
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

    data["cpu_memory"] = json.dumps(
        {
            "resource": resource,
            "health": health,
        },
        ensure_ascii=False,
    )

    # --------------------------------------------------------
    # Wireless static configuration
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

    data["ssid"] = first_nonempty(
        kv.get("ssid"),
    )

    data["interface_name"] = first_nonempty(
        kv.get("name"),
    )

    data["mode"] = first_nonempty(
        kv.get("mode"),
    )

    data["mac_address"] = normalize_mac(
        kv.get("mac-address", "")
    )

    data["tx_power_mode"] = first_nonempty(
        kv.get("tx-power-mode"),
    )

    data["antenna_gain"] = first_nonempty(
        kv.get("antenna-gain"),
    )

    data["polarization"] = first_nonempty(
        kv.get("polarization"),
    )

    data["modulation"] = first_nonempty(
        kv.get("modulation"),
    )

    data["capacity"] = first_nonempty(
        kv.get("capacity"),
    )

    # Do not take `current-tx-powers` from interface config:
    # on RouterOS 6 it can be a per-rate table rather than a scalar.
    configured_tx_power = first_nonempty(
        kv.get("tx-power"),
        kv.get("output-power"),
    )

    if configured_tx_power and not re.search(
        r"\d+\s*Mbps\s*:",
        configured_tx_power,
        re.I,
    ):
        data["tx_power"] = configured_tx_power

    # --------------------------------------------------------
    # Live monitor
    # --------------------------------------------------------

    monitor_data, monitor_raw = (
        mikrotik_wireless_monitor(client)
    )

    interface_data, interface_raw = (
        mikrotik_wireless_interface(client)
    )

    # Static interface values first.
    merge_missing(
        data,
        interface_data,
    )

    # Live values ALWAYS override stale/config values.
    for key in (
        "ssid",
        "frequency",
        "channel",
        "bandwidth",
        "mode",
        "wireless_status",
        "rx_power",
        "receive_power",
        "signal_strength",
        "signal_strength_ch0",
        "signal_strength_ch1",
        "peer_tx_signal",
        "peer_tx_signal_ch0",
        "peer_tx_signal_ch1",
        "noise_floor",
        "snr",
        "ccq",
        "rx_ccq",
        "tx_ccq",
        "tx_rate",
        "rx_rate",
        "distance",
        "mac_address",
        "wds_link",
        "bridge",
    ):
        value = monitor_data.get(key)

        if not missing(value):
            data[key] = value

    # Explicit local scalar TX power only.
    if not missing(monitor_data.get("tx_power")):
        data["tx_power"] = monitor_data["tx_power"]
    elif not missing(interface_data.get("tx_power")):
        data["tx_power"] = interface_data["tx_power"]
    elif not missing(configured_tx_power):
        data["tx_power"] = configured_tx_power
    else:
        data["tx_power"] = ""

    # Configuration field, independent from TX power itself.
    if not missing(interface_data.get("tx_power_mode")):
        data["tx_power_mode"] = interface_data["tx_power_mode"]

    if missing(data.get("tx_power_mode")):
        data["tx_power_mode"] = ""

    # --------------------------------------------------------
    # Determine AP vs Station
    # --------------------------------------------------------

    mode_text = safe_text(
        data.get("mode")
    ).lower()

    status_text = safe_text(
        data.get("wireless_status")
    ).lower()

    is_ap = (
        mode_text in {
            "ap-bridge",
            "ap-bridge-master",
            "bridge",
            "ap",
        }
        or "running-ap" in status_text
    )

    is_station = (
        "station" in mode_text
        or "connected-to-ess" in status_text
        or "connected" in status_text
    )

    # --------------------------------------------------------
    # Registration table
    # --------------------------------------------------------

    registration_clients, registration_raw = (
        mikrotik_registration_clients(client)
    )

    data["wireless_registration"] = registration_raw

    # --------------------------------------------------------
    # AP logic
    # --------------------------------------------------------
    #
    # AP monitor usually only tells us local radio state:
    # channel/noise/registered-clients.
    #
    # Peer signal and link quality come from registration-table.

    selected_registration = None

    if is_ap and registration_clients:
        # Point-to-point deployments normally have one client.
        # For multi-client APs, use the first valid record rather
        # than inventing a combined signal value.
        selected_registration = registration_clients[0]

        registration_runtime = _registration_to_runtime(
            selected_registration
        )

        for key, value in registration_runtime.items():
            if not missing(value):
                data[key] = value

    # --------------------------------------------------------
    # Station logic
    # --------------------------------------------------------
    #
    # Station monitor is the authoritative source.
    # Registration table is only a fallback when a live field
    # is absent.

    elif is_station:
        if registration_clients:

            selected_registration = (
                registration_clients[0]
            )

            registration_runtime = (
                _registration_to_runtime(
                    selected_registration
                )
            )

            for key, value in registration_runtime.items():

                # Never overwrite live Station monitor data
                # with registration fallback.
                if missing(data.get(key)):
                    data[key] = value

    # --------------------------------------------------------
    # Generic fallback
    # --------------------------------------------------------

    else:
        if registration_clients:
            selected_registration = (
                registration_clients[0]
            )

            registration_runtime = (
                _registration_to_runtime(
                    selected_registration
                )
            )

            for key, value in registration_runtime.items():
                if missing(data.get(key)):
                    data[key] = value

    # --------------------------------------------------------
    # Ensure frequency / bandwidth are normalized
    # --------------------------------------------------------

    if data.get("channel"):
        freq, bw = channel_parts(
            data["channel"]
        )

        if freq:
            data["frequency"] = freq

        if bw and missing(data.get("bandwidth")):
            data["bandwidth"] = bw

    # Frequency should be numeric without MHz.
    if data.get("frequency"):
        data["frequency"] = re.sub(
            r"\s*MHz$",
            "",
            safe_text(data["frequency"]),
            flags=re.I,
        ).strip()

    # --------------------------------------------------------
    # Normalize RF strings
    # --------------------------------------------------------

    for field in (
        "rx_power",
        "receive_power",
        "signal_strength",
        "signal_strength_ch0",
        "signal_strength_ch1",
        "peer_tx_signal",
        "peer_tx_signal_ch0",
        "peer_tx_signal_ch1",
        "noise_floor",
    ):
        if not missing(data.get(field)):
            data[field] = normalize_dbm(
                data[field]
            )

    # --------------------------------------------------------
    # Dashboard compatibility
    # --------------------------------------------------------

    # Existing dashboard field.
    if missing(data.get("receive_power")):
        data["receive_power"] = safe_text(
            data.get("rx_power")
        )

    if missing(data.get("rx_power")):
        data["rx_power"] = safe_text(
            data.get("receive_power")
        )

    if missing(data.get("signal_strength")):
        # Never manufacture signal from peer TX.
        data["signal_strength"] = ""

    if missing(data.get("ccq")):
        data["ccq"] = ""

    if missing(data.get("noise_floor")):
        data["noise_floor"] = ""

    if missing(data.get("peer_tx_signal")):
        data["peer_tx_signal"] = ""

    # IMPORTANT:
    # Never copy peer_tx_signal into tx_power.
    if data.get("peer_tx_signal") and (
        safe_text(data.get("tx_power"))
        == safe_text(data.get("peer_tx_signal"))
    ):
        data["tx_power"] = ""

    # Never expose a rate-table as the dashboard TX Power.
    if re.search(
        r"\d+\s*Mbps\s*:",
        safe_text(data.get("tx_power")),
        re.I,
    ):
        data["tx_power"] = ""

    # --------------------------------------------------------
    # TEMPORARY MikroTik RF simulation
    # --------------------------------------------------------
    # Fill ONLY missing fields. Real RouterOS values always win.
    simulated_rf = {}

    if MIKROTIK_PLACEHOLDER_ENABLED:
        simulated_tx, simulated_rx = _simulated_rf_values(
            ip,
            data.get("signal_strength") or data.get("rx_power"),
        )

        if missing(data.get("tx_power")):
            data["tx_power"] = simulated_tx
            simulated_rf["tx_power"] = {
                "value": simulated_tx,
                "source": "SIMULATED_TEMPORARY",
            }

        if missing(data.get("rx_power")):
            data["rx_power"] = simulated_rx
            simulated_rf["rx_power"] = {
                "value": simulated_rx,
                "source": "SIMULATED_TEMPORARY",
            }

    # Keep the legacy dashboard field in sync.
    if missing(data.get("receive_power")):
        data["receive_power"] = data.get("rx_power", "")

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

    data["pppoe_vpn"] = "\n".join(
        x
        for x in (
            pppoe,
            l2tp,
            sstp,
            ovpn,
        )
        if x
    ).strip()

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
    # Preserve extra wireless fields in raw_data.
    #
    # The existing database schema does not have columns for:
    # peer_tx_signal, tx_power_mode, snr, chain values, etc.
    # Keeping them here makes them available to the API's
    # raw_data_parsed for the existing application.
    # --------------------------------------------------------

    data["raw_data"] = json.dumps(
        {
            "identity": identity,
            "resource": resource,
            "wireless": wireless,
            "wifi": wifi,
            "wireless_monitor": monitor_raw,
            "wireless_interface": interface_raw,
            "registration": registration_raw,
            "registration_clients": registration_clients,
            "selected_registration": selected_registration,
            "role": (
                "ap"
                if is_ap
                else "station"
                if is_station
                else "unknown"
            ),
            "snmp_radio": {
                "note": (
                    "MikroTik wireless RF metrics are read from RouterOS "
                    "runtime/configuration, not the old hard-coded SNMP OIDs."
                )
            },
            "simulated_rf": simulated_rf,
            "dashboard_fields": {
                "tx_power": data.get("tx_power", ""),
                "rx_power": data.get("rx_power", ""),
                "signal_strength": data.get("signal_strength", ""),
                "peer_tx_signal": data.get("peer_tx_signal", ""),
                "tx_power_mode": data.get("tx_power_mode", ""),
                "noise_floor": data.get("noise_floor", ""),
                "ccq": data.get("ccq", ""),
                "snr": data.get("snr", ""),
                "frequency": data.get("frequency", ""),
                "channel": data.get("channel", ""),
                "bandwidth": data.get("bandwidth", ""),
                "mode": data.get("mode", ""),
            },
        },
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

    version = run_cmd(client, "show version")
    hostname = run_cmd(client, "show running-config | include ^hostname")
    int_brief = run_cmd(client, "show ip interface brief")
    int_description = run_cmd(client, "show interfaces description")
    mac = run_cmd(client, "show interfaces")

    hostname_match = re.search(r"^([\w.\-]+)\s+uptime", version, re.M)
    model_match = re.search(r"[Cc]isco\s+([\w/-]+)", version)
    mac_match = re.search(r"([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})", mac, re.I)

    data["hostname"] = first_nonempty(
        first_value(hostname, "hostname"),
        hostname_match.group(1) if hostname_match else "",
    )
    data["firmware_version"] = first_value(version, "Version")
    data["model"] = model_match.group(1) if model_match else ""
    data["uptime"] = first_value(version, "uptime is")
    data["interfaces"] = int_brief + "\n" + int_description
    data["mac_address"] = normalize_mac(mac_match.group(1) if mac_match else "")
    data["raw_data"] = json.dumps(
        {"version": version[:4000], "interfaces": int_brief[:4000], "descriptions": int_description[:3000]},
        ensure_ascii=False,
    )
    data["scan_status"] = "success"
    return data


# ============================================================
# Racom
# ============================================================
# ============================================================
# RACOM SNMP FIX
# Replace the existing RACOM/SNMP detection section in scanner.py
# ============================================================

RACOM_ENTERPRISE_OID = "1.3.6.1.4.1.33555"

# RAy2 root:
# 1.3.6.1.4.1.33555.1
#
# RAy3 root:
# 1.3.6.1.4.1.33555.4
#
# RACOM RAY-MIB / RAY3-MIB:
# productName, serialNumber, deviceName, swVer, MAC,
# rxFreq, txFreq, txChannel, rfPowerCurrent, rss, snr, ...
#
# RACOM official documentation:
# https://www.racom.eu/eng/products/m/ray/app/snmp/SNP_protokol.html
# https://www.racom.eu/eng/products/m/ray/app/snmp-ray3/ray3.html

def _racom_oid(root, *parts):
    return ".".join(
        [RACOM_ENTERPRISE_OID, str(root)] + [str(x) for x in parts]
    )


def _parse_int(value):
    if missing(value):
        return None

    text = safe_text(value)

    text = re.sub(
        r"^(INTEGER|Gauge32|Integer32|Counter32|Counter64|Timeticks):\s*",
        "",
        text,
        flags=re.I,
    ).strip()

    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return None

    try:
        return float(match.group(0))
    except Exception:
        return None


def _format_dbm(value):
    number = _parse_int(value)

    if number is None:
        return ""

    return f"{number:g} dBm"


def _format_mhz_from_khz(value):
    number = _parse_int(value)

    if number is None:
        return ""

    # RACOM reports radio frequency in kHz.
    mhz = number / 1000.0

    return f"{mhz:g}"


def _format_mhz_from_khz_with_unit(value):
    number = _parse_int(value)

    if number is None:
        return ""

    mhz = number / 1000.0

    return f"{mhz:g} MHz"


def _format_tenths(value, unit=""):
    number = _parse_int(value)

    if number is None:
        return ""

    number = number / 10.0

    if unit:
        return f"{number:g} {unit}"

    return f"{number:g}"


def _format_hundredths(value, unit=""):
    number = _parse_int(value)

    if number is None:
        return ""

    number = number / 100.0

    if unit:
        return f"{number:g} {unit}"

    return f"{number:g}"


def _racom_root_from_object_id(sys_object_id=""):
    """
    RACOM:
      RAy2 -> 1.3.6.1.4.1.33555.1
      RAy3 -> 1.3.6.1.4.1.33555.4
    """

    oid = safe_text(sys_object_id).strip()

    if oid.startswith(f"{RACOM_ENTERPRISE_OID}.4"):
        return "4"

    if oid.startswith(f"{RACOM_ENTERPRISE_OID}.1"):
        return "1"

    return ""


def _racom_detected_by_text(sys_descr="", sys_object_id=""):
    text = (
        safe_text(sys_descr)
        + " "
        + safe_text(sys_object_id)
    ).lower()

    if "racom" in text:
        return True

    if "microwave link" in text:
        return True

    if "ray2" in text:
        return True

    if "ray3" in text:
        return True

    if RACOM_ENTERPRISE_OID in text:
        return True

    return False


def _racom_oid_map(root):
    """
    Build all RACOM RAy2 / RAy3 scalar OIDs.

    RAy2:
      33555.1

    RAy3:
      33555.4
    """

    return {
        # ----------------------------------------------------
        # Product
        # ----------------------------------------------------
        "product_name": _racom_oid(root, 1, 1, 1, 0),
        "serial_number": _racom_oid(root, 1, 1, 2, 0),
        "unit_type": _racom_oid(root, 1, 1, 3, 0),

        # ----------------------------------------------------
        # Info
        # ----------------------------------------------------
        "device_name": _racom_oid(root, 1, 2, 1, 0),
        "sw_ver": _racom_oid(root, 1, 2, 2, 0),
        "sw_ver_radio": _racom_oid(root, 1, 2, 3, 0),

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------
        "system_status": _racom_oid(root, 1, 3, 1, 0),
        "peer_number": _racom_oid(root, 1, 3, 3, 0),
        "line_status_ii": _racom_oid(root, 1, 3, 8, 0),
        "secure_peer_mode": _racom_oid(root, 1, 3, 7, 0),
        "eth1_link": _racom_oid(root, 1, 3, 9, 0),
        "eth2_link": _racom_oid(root, 1, 3, 10, 0),

        # ----------------------------------------------------
        # Chassis
        # ----------------------------------------------------
        "temperature_modem": _racom_oid(root, 1, 4, 1, 0),
        "temperature_radio": _racom_oid(root, 1, 4, 2, 0),
        "voltage_unit": _racom_oid(root, 1, 4, 3, 0),
        "voltage_source": _racom_oid(root, 1, 4, 4, 0),

        # ----------------------------------------------------
        # System
        # ----------------------------------------------------
        "cpu": _racom_oid(root, 1, 5, 1, 0),
        "memory": _racom_oid(root, 1, 5, 2, 0),
        "log_storage": _racom_oid(root, 1, 5, 3, 0),

        # ----------------------------------------------------
        # Access
        # ----------------------------------------------------
        "access_ip": _racom_oid(root, 1, 6, 4, 0),
        "access_mac": _racom_oid(root, 1, 6, 5, 0),
        "management_vlan": _racom_oid(root, 1, 6, 6, 0),
        "management_vlan_id": _racom_oid(root, 1, 6, 7, 0),
        "wifi_hap": _racom_oid(root, 1, 6, 8, 0),

        # ----------------------------------------------------
        # Radio interface
        # ----------------------------------------------------
        "rx_channel": _racom_oid(root, 2, 1, 1, 0),
        "tx_channel": _racom_oid(root, 2, 1, 2, 0),
        "rx_freq": _racom_oid(root, 2, 1, 3, 0),
        "tx_freq": _racom_oid(root, 2, 1, 4, 0),
        "rx_modulation": _racom_oid(root, 2, 1, 5, 0),
        "tx_modulation": _racom_oid(root, 2, 1, 6, 0),
        "rx_modulation_index": _racom_oid(root, 2, 1, 7, 0),
        "tx_modulation_index": _racom_oid(root, 2, 1, 8, 0),
        "rf_power_configured": _racom_oid(root, 2, 1, 12, 0),
        "net_bitrate": _racom_oid(root, 2, 1, 13, 0),
        "max_net_bitrate": _racom_oid(root, 2, 1, 14, 0),
        "tx_bandwidth_khz": _racom_oid(root, 2, 1, 15, 0),
        "channel_arrangement": _racom_oid(root, 2, 1, 16, 0),
        "rf_power_current": _racom_oid(root, 2, 1, 17, 0),

        # RAy3 additions
        "acm": _racom_oid(root, 2, 1, 18, 0),
        "atpc": _racom_oid(root, 2, 1, 19, 0),
        "frequency_table": _racom_oid(root, 2, 1, 20, 0),
        "rx_bandwidth_khz": _racom_oid(root, 2, 1, 21, 0),

        # ----------------------------------------------------
        # Radio statistics
        # ----------------------------------------------------
        "rss": _racom_oid(root, 3, 2, 1, 0),
        "snr": _racom_oid(root, 3, 2, 2, 0),
        "time_all_connect": _racom_oid(root, 3, 2, 5, 0),
        "time_all_disconnect": _racom_oid(root, 3, 2, 6, 0),
        "time_max_disconnect": _racom_oid(root, 3, 2, 7, 0),
        "num_disconnect": _racom_oid(root, 3, 2, 8, 0),
        "reliability": _racom_oid(root, 3, 2, 9, 0),
        "link_uptime": _racom_oid(root, 3, 2, 10, 0),
        "ber": _racom_oid(root, 3, 2, 11, 0),

        # RAy3
        "mse": _racom_oid(root, 3, 2, 12, 0),

        # ----------------------------------------------------
        # Ethernet statistics
        # ----------------------------------------------------
        "eth_in_throughput": _racom_oid(root, 3, 3, 1, 0),
        "eth_out_throughput": _racom_oid(root, 3, 3, 2, 0),
        "eth2_in_throughput": _racom_oid(root, 3, 3, 3, 0),
        "eth2_out_throughput": _racom_oid(root, 3, 3, 4, 0),
    }


def racom_snmp_info(ip, sys_object_id=""):
    """
    Real RACOM SNMP reader.

    Supports:
      - RAy2
      - RAy3
    """

    roots_to_try = []

    detected_root = _racom_root_from_object_id(
        sys_object_id
    )

    if detected_root:
        roots_to_try.append(detected_root)

    # Fallback order.
    for root in ("4", "1"):
        if root not in roots_to_try:
            roots_to_try.append(root)

    last_raw = {}

    for root in roots_to_try:
        oids = _racom_oid_map(root)

        result = snmp_get(
            ip,
            list(oids.values()),
        )

        values = result.get("values", {})

        if not values:
            continue

        reverse = {
            oid: name
            for name, oid in oids.items()
        }

        by_name = {}

        for oid, value in values.items():
            name = reverse.get(oid)

            if name:
                by_name[name] = value

        last_raw = {
            "root": root,
            "values": by_name,
            "credential_id": result.get(
                "credential_id",
                "",
            ),
            "community": result.get(
                "community",
                "",
            ),
        }

        # Need at least one real RACOM field.
        racom_markers = (
            "product_name",
            "device_name",
            "sw_ver",
            "access_mac",
            "rx_freq",
            "tx_freq",
            "rss",
        )

        if not any(
            not missing(by_name.get(marker))
            for marker in racom_markers
        ):
            continue

        data = {
            "ip_address": ip,
            "device_type": (
                "Racom RAy3"
                if root == "4"
                else "Racom RAy2"
            ),
            "vendor": "Racom",

            # ------------------------------------------------
            # Basic information
            # ------------------------------------------------
            "hostname": first_nonempty(
                by_name.get("device_name"),
            ),

            "model": first_nonempty(
                by_name.get("product_name"),
            ),

            "firmware_version": first_nonempty(
                by_name.get("sw_ver"),
                by_name.get("sw_ver_radio"),
            ),

            "serial_number": first_nonempty(
                by_name.get("serial_number"),
            ),

            "mac_address": normalize_mac(
                first_nonempty(
                    by_name.get("access_mac"),
                )
            ),

            # ------------------------------------------------
            # RF
            # ------------------------------------------------
            "channel": first_nonempty(
                by_name.get("tx_channel"),
                by_name.get("rx_channel"),
            ),

            "frequency": first_nonempty(
                _format_mhz_from_khz(
                    by_name.get("tx_freq")
                ),
                _format_mhz_from_khz(
                    by_name.get("rx_freq")
                ),
            ),

            "tx_power": first_nonempty(
                _format_dbm(
                    by_name.get("rf_power_current")
                ),
                _format_dbm(
                    by_name.get("rf_power_configured")
                ),
            ),

            "rx_power": first_nonempty(
                _format_tenths(
                    by_name.get("rss"),
                    "dBm",
                ),
            ),

            "receive_power": first_nonempty(
                _format_tenths(
                    by_name.get("rss"),
                    "dBm",
                ),
            ),

            "signal_strength": first_nonempty(
                _format_tenths(
                    by_name.get("rss"),
                    "dBm",
                ),
            ),

            "snr": first_nonempty(
                _format_tenths(
                    by_name.get("snr"),
                    "dB",
                ),
            ),

            "bandwidth": "",

            "ssid": "",

            "mode": "",

            "peer_tx_signal": "",

            "noise_floor": "",

            "ccq": "",

            "tx_power_mode": "",

            # ------------------------------------------------
            # Status
            # ------------------------------------------------
            "scan_status": "success",
        }

        # ----------------------------------------------------
        # Bandwidth
        # ----------------------------------------------------

        bandwidth_khz = _parse_int(
            by_name.get("tx_bandwidth_khz")
        )

        if bandwidth_khz is None:
            bandwidth_khz = _parse_int(
                by_name.get("rx_bandwidth_khz")
            )

        if bandwidth_khz is not None and bandwidth_khz > 0:
            data["bandwidth"] = (
                f"{bandwidth_khz / 1000.0:g} MHz"
            )

        # RAy2 has an enum bandwidth instead of
        # txBandwidthKHz.
        if missing(data.get("bandwidth")):
            bandwidth_enum = _parse_int(
                by_name.get("bandwidth")
            )

            if bandwidth_enum == 1:
                data["bandwidth"] = "28 MHz"
            elif bandwidth_enum == 2:
                data["bandwidth"] = "14 MHz"
            elif bandwidth_enum == 3:
                data["bandwidth"] = "7 MHz"

        # ----------------------------------------------------
        # TX power mode
        # ----------------------------------------------------

        atpc = _parse_int(
            by_name.get("atpc")
        )

        if atpc == 1:
            data["tx_power_mode"] = "ATPC ON"
        elif atpc == 2:
            data["tx_power_mode"] = "ATPC OFF"

        # ----------------------------------------------------
        # Radio modulation can be useful as mode.
        # ----------------------------------------------------

        modulation = first_nonempty(
            by_name.get("tx_modulation"),
            by_name.get("rx_modulation"),
        )

        if modulation:
            data["mode"] = modulation

        # ----------------------------------------------------
        # Frequency normalization
        # ----------------------------------------------------

        if data.get("frequency"):
            data["frequency"] = re.sub(
                r"\s*MHz\s*$",
                "",
                safe_text(data["frequency"]),
                flags=re.I,
            ).strip()

        # ----------------------------------------------------
        # Serial fallback
        # ----------------------------------------------------

        if missing(data.get("serial_number")):
            data["serial_number"] = first_nonempty(
                data.get("mac_address"),
            )

        # ----------------------------------------------------
        # Raw data
        # ----------------------------------------------------

        data["raw_data"] = json.dumps(
            {
                "mode": "racom-snmp",
                "product": (
                    "RAy3"
                    if root == "4"
                    else "RAy2"
                ),
                "root": root,
                "oid_base": (
                    f"{RACOM_ENTERPRISE_OID}.{root}"
                ),
                "snmp": last_raw,
                "dashboard_fields": {
                    "hostname": data.get(
                        "hostname",
                        "",
                    ),
                    "model": data.get(
                        "model",
                        "",
                    ),
                    "firmware_version": data.get(
                        "firmware_version",
                        "",
                    ),
                    "serial_number": data.get(
                        "serial_number",
                        "",
                    ),
                    "mac_address": data.get(
                        "mac_address",
                        "",
                    ),
                    "ssid": data.get(
                        "ssid",
                        "",
                    ),
                    "frequency": data.get(
                        "frequency",
                        "",
                    ),
                    "tx_power": data.get(
                        "tx_power",
                        "",
                    ),
                    "rx_power": data.get(
                        "rx_power",
                        "",
                    ),
                    "signal_strength": data.get(
                        "signal_strength",
                        "",
                    ),
                    "channel": data.get(
                        "channel",
                        "",
                    ),
                    "bandwidth": data.get(
                        "bandwidth",
                        "",
                    ),
                    "mode": data.get(
                        "mode",
                        "",
                    ),
                    "peer_tx_signal": data.get(
                        "peer_tx_signal",
                        "",
                    ),
                    "tx_power_mode": data.get(
                        "tx_power_mode",
                        "",
                    ),
                    "noise_floor": data.get(
                        "noise_floor",
                        "",
                    ),
                    "ccq": data.get(
                        "ccq",
                        "",
                    ),
                    "snr": data.get(
                        "snr",
                        "",
                    ),
                },
            },
            ensure_ascii=False,
        )

        return (
            data,
            f"snmp:{result.get('credential_id', 'unknown')}",
        )

    raise RuntimeError(
        "RACOM SNMP OIDs returned no usable data"
    )


# ============================================================
# SNMP credential fix
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
                                "id": (
                                    f"json-{len(out) + 1}"
                                ),
                            })

                    elif isinstance(item, dict):
                        community = safe_text(
                            item.get("community")
                        )

                        if community:
                            out.append({
                                "community": community,
                                "id": item.get(
                                    "id",
                                    f"json-{len(out) + 1}",
                                ),
                            })

        except Exception as exc:
            logger.warning(
                "Invalid SNMP_COMMUNITIES_JSON: %s",
                exc,
            )

    # User-configured community first.
    if SNMP_COMMUNITY.strip():
        out.append({
            "community": SNMP_COMMUNITY.strip(),
            "id": "ngstehwl",
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
# SNMP detection - FIXED
# ============================================================

def detect_from_snmp(
    sys_descr,
    sys_object_id="",
):
    text = (
        safe_text(sys_descr)
        + " "
        + safe_text(sys_object_id)
    ).lower()

    # RACOM MUST BE BEFORE generic "unknown".
    if _racom_detected_by_text(
        sys_descr,
        sys_object_id,
    ):
        return "racom"

    if "mikrotik" in text:
        return "mikrotik"

    if "routeros" in text:
        return "mikrotik"

    if "cisco" in text:
        return "cisco"

    if "ios" in text:
        return "cisco"

    if "nx-os" in text:
        return "cisco"

    return "unknown"


# ============================================================
# SNMP-only fallback - FIXED
# ============================================================

def snmp_only_info(ip):
    if not SNMP_ENABLED:
        raise RuntimeError(
            "SNMP disabled"
        )

    standard_data, standard_raw, standard_result = (
        snmp_standard_info(ip)
    )

    if not standard_result.get("values"):
        raise RuntimeError(
            "SNMP unavailable"
        )

    values = standard_result.get(
        "values",
        {},
    )

    sys_descr = safe_text(
        values.get(
            SNMP_OIDS["sysDescr"]
        )
    )

    sys_object_id = safe_text(
        values.get(
            SNMP_OIDS["sysObjectID"]
        )
    )

    # --------------------------------------------------------
    # RACOM
    # --------------------------------------------------------

    if _racom_detected_by_text(
        sys_descr,
        sys_object_id,
    ):
        data, credential_id = (
            racom_snmp_info(
                ip,
                sys_object_id,
            )
        )

        # Keep standard values that RACOM does not supply.
        merge_missing(
            data,
            standard_data,
        )

        # RACOM values are authoritative.
        data["vendor"] = "Racom"

        root = _racom_root_from_object_id(
            sys_object_id
        )

        if root == "4":
            data["device_type"] = "Racom RAy3"
        else:
            data["device_type"] = "Racom RAy2"

        data["scan_status"] = "success"

        try:
            raw = json.loads(
                data.get(
                    "raw_data",
                    "{}",
                )
            )

            if not isinstance(
                raw,
                dict,
            ):
                raw = {}

        except Exception:
            raw = {}

        raw["standard_snmp"] = standard_raw
        raw["sys_descr"] = sys_descr
        raw["sys_object_id"] = sys_object_id

        data["raw_data"] = json.dumps(
            raw,
            ensure_ascii=False,
        )

        return data, credential_id

    # --------------------------------------------------------
    # Mimosa
    # --------------------------------------------------------

    mimosa_detect = detect_mimosa_c5c(ip)

    if mimosa_detect.get("is_mimosa"):
        radio_data, radio_raw = (
            mimosa_c5c_snmp_radio(ip)
        )

        if not radio_data:
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

        merge_missing(
            data,
            standard_data,
        )

        merge_missing(
            data,
            radio_data,
        )

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
            if not missing(
                radio_data.get(field)
            ):
                data[field] = radio_data[field]

        data["raw_data"] = json.dumps(
            {
                "snmp": standard_raw,
                "mimosa": radio_raw,
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
    # Generic SNMP
    # --------------------------------------------------------

    device_type = detect_from_snmp(
        sys_descr,
        sys_object_id,
    )

    data = {
        "ip_address": ip,
        "device_type": {
            "mikrotik": "MikroTik",
            "cisco": "Cisco",
            "racom": "Racom",
        }.get(
            device_type,
            "Unknown",
        ),
        "vendor": {
            "mikrotik": "MikroTik",
            "cisco": "Cisco",
            "racom": "Racom",
        }.get(
            device_type,
            "",
        ),
        "scan_status": "success",
    }

    merge_missing(
        data,
        standard_data,
    )

    data["mac_address"] = normalize_mac(
        data.get(
            "mac_address",
            "",
        )
    )

    data["raw_data"] = json.dumps(
        {
            "snmp": standard_raw,
            "mode": "snmp-only",
            "sys_descr": sys_descr,
            "sys_object_id": sys_object_id,
        },
        ensure_ascii=False,
    )

    return (
        data,
        f"snmp:{standard_result.get('credential_id', 'unknown')}",
    )


# ============================================================
# OPTIONAL: make RACOM work even if sysDescr is only
# "Microwave Link"
# ============================================================

def snmp_standard_info(ip):
    result = snmp_get(
        ip,
        list(SNMP_OIDS.values()),
    )

    values = result.get(
        "values",
        {},
    )

    reverse = {
        oid: name
        for name, oid in SNMP_OIDS.items()
    }

    by_name = {
        reverse.get(
            oid,
            oid,
        ): value
        for oid, value in values.items()
    }

    data = {
        "hostname": first_nonempty(
            by_name.get("sysName")
        ),

        "firmware_version": first_nonempty(
            by_name.get("sysDescr")
        ),

        "uptime": first_nonempty(
            by_name.get("sysUpTime")
        ),

        "mac_address": normalize_mac(
            by_name.get(
                "ifPhysAddress.1"
            )
        ),
    }

    raw = {
        "system": by_name,
        "credential_id": result.get(
            "credential_id"
        ),
        "community": result.get(
            "community"
        ),
    }

    return (
        data,
        raw,
        result,
    )


# ============================================================
# IMPORTANT:
# Keep the existing scan_single_ip() exactly as it is.
#
# This existing code already does:
#
#     try SSH
#     ...
#     except:
#         SNMP fallback
#
# and now snmp_only_info() recognizes RACOM correctly.
# ============================================================

# ============================================================
# Detection
# ============================================================

def detect(client):
    output = run_cmd(client, "/system identity print")
    if output and ("name:" in output.lower() or "routeros" in output.lower()):
        return "mikrotik"

    output = run_cmd(client, "show version")
    if output and any(x in output.lower() for x in ("cisco", "ios", "nx-os")):
        return "cisco"

    output = run_cmd(client, "show system")
    if output and any(x in output.lower() for x in ("racom", "ripex")):
        return "racom"

    return "unknown"


def detect_from_snmp(sys_descr, sys_object_id=""):
    text = (safe_text(sys_descr) + " " + safe_text(sys_object_id)).lower()
    if "mikrotik" in text or "routeros" in text:
        return "mikrotik"
    if "cisco" in text or "ios" in text or "nx-os" in text:
        return "cisco"
    if "racom" in text or "ripex" in text:
        return "racom"
    return "unknown"


# ============================================================
# SNMP-only fallback
# ============================================================

def snmp_only_info(ip):
    if not SNMP_ENABLED:
        raise RuntimeError("SNMP disabled")

    standard_data, standard_raw, standard_result = snmp_standard_info(ip)
    if not standard_result.get("values"):
        raise RuntimeError("SNMP unavailable")

    values = standard_result.get("values", {})
    sys_descr = safe_text(values.get(SNMP_OIDS["sysDescr"]))
    sys_object_id = safe_text(values.get(SNMP_OIDS["sysObjectID"]))

    mimosa_detect = detect_mimosa_c5c(ip)
    if mimosa_detect.get("is_mimosa"):
        radio_data, radio_raw = mimosa_c5c_snmp_radio(ip)
        if not radio_data:
            raise RuntimeError("Mimosa C5c SNMP unavailable")

        data = {
            "ip_address": ip,
            "device_type": "Mimosa C5c",
            "vendor": "Mimosa",
            "model": "C5c",
            "scan_status": "success",
        }
        merge_missing(data, standard_data)
        merge_missing(data, radio_data)
        for field in (
            "hostname", "firmware_version", "serial_number",
            "mac_address", "ssid", "frequency", "bandwidth",
            "mode", "tx_power", "rx_power", "receive_power",
            "signal_strength", "noise_floor", "snr",
        ):
            if not missing(radio_data.get(field)):
                data[field] = radio_data[field]

        data["raw_data"] = json.dumps(
            {
                "snmp": standard_raw,
                "mimosa": radio_raw,
                "mode": "mimosa-c5c-snmp",
                "sys_descr": sys_descr,
                "sys_object_id": sys_object_id,
            },
            ensure_ascii=False,
        )
        return data, f"snmp:{standard_result.get('credential_id', 'unknown')}"

    device_type = detect_from_snmp(sys_descr, sys_object_id)
    data = {
        "ip_address": ip,
        "device_type": {
            "mikrotik": "MikroTik",
            "cisco": "Cisco",
            "racom": "Racom",
        }.get(device_type, "Unknown"),
        "vendor": {
            "mikrotik": "MikroTik",
            "cisco": "Cisco",
            "racom": "Racom",
        }.get(device_type, ""),
        "scan_status": "success",
    }
    merge_missing(data, standard_data)
    data["mac_address"] = normalize_mac(data.get("mac_address", ""))
    data["raw_data"] = json.dumps(
        {"snmp": standard_raw, "mode": "snmp-only"},
        ensure_ascii=False,
    )
    return data, f"snmp:{standard_result.get('credential_id', 'unknown')}"


# ============================================================
# Single scan
# ============================================================

def scan_single_ip(ip):
    if is_blacklisted(ip):
        return "skipped", ip, None

    if not host_is_alive(ip):
        return "not_alive", ip, None

    client = None
    credential_id = ""
    ssh_error = ""

    try:
        client, credential_id = ssh_connect(ip)
        device_type = detect(client)

        if device_type == "mikrotik":
            data = routeros_info(ip, client)
        elif device_type == "cisco":
            data = cisco_info(ip, client)
        elif device_type == "racom":
            data = racom_info(ip, client)
        else:
            data = {
                "ip_address": ip,
                "device_type": "Unknown",
                "scan_status": "unknown_type",
            }

        data["credential_id"] = credential_id
        row = upsert_device(data)

        return "success", ip, dict(row) if row else data

    except Exception as exc:
        ssh_error = str(exc)[:200]

    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass

    # SNMP-only fallback.
    if SNMP_ENABLED:
        try:
            data, snmp_credential_id = snmp_only_info(ip)
            data["credential_id"] = snmp_credential_id

            try:
                raw = json.loads(data.get("raw_data", "{}"))
                if not isinstance(raw, dict):
                    raw = {}
            except Exception:
                raw = {}

            raw["ssh_fallback_error"] = ssh_error
            raw["data_merge"] = "SNMP-only fallback"
            data["raw_data"] = json.dumps(raw, ensure_ascii=False)

            row = upsert_device(data)
            return "success", ip, dict(row) if row else data

        except Exception as exc:
            error_text = (
                f"SSH: {ssh_error} | SNMP: {str(exc)[:150]}"
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

    return "failed", ip, {"error": error_text}


# ============================================================
# Full scan
# ============================================================

def run_scan(target_ips=None):
    init_db()
    start = time.time()

    all_ips = target_ips or get_all_ips()
    all_ips = [ip for ip in all_ips if not is_blacklisted(ip)]

    alive = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(100, len(all_ips) or 1)
    ) as executor:
        futures = {executor.submit(host_is_alive, ip): ip for ip in all_ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result() and not is_blacklisted(ip):
                    alive.append(ip)
            except Exception:
                pass

    snapshots = []
    success = 0
    failed = 0

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, SCAN_WORKERS)
    ) as executor:
        futures = {
            executor.submit(scan_single_ip, ip): ip
            for ip in alive
        }
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                status, ip, snapshot = future.result()
            except Exception as exc:
                status = "failed"
                snapshot = {"error": str(exc)[:200]}

            if status == "success":
                success += 1
            elif status == "failed":
                failed += 1

            snapshots.append((ip, status, snapshot or {}))

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
        [{"username": c.get("username"), "id": c.get("id")} for c in CREDENTIALS],
    )
    print("Legacy SSH:", "enabled" if LEGACY_SSH_FALLBACK else "disabled")
    print("OpenSSH:", shutil.which("ssh") or "NOT FOUND")
    print("sshpass:", shutil.which("sshpass") or "NOT FOUND")
    print("SNMP:", "enabled" if SNMP_ENABLED else "disabled")
    print("SNMP Version:", SNMP_VERSION)
    print("SNMP Port:", SNMP_PORT)
    print("PySNMP:", "available" if SnmpDispatcher else "NOT INSTALLED")
    print("=" * 60)

    print(run_scan())
