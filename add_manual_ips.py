#!/usr/bin/env python3

import json
import os
import ipaddress


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

IPS_FILE = os.path.join(
    BASE_DIR,
    "manual_ips.txt"
)

JSON_FILE = os.path.join(
    BASE_DIR,
    "manual_devices.json"
)


def load_ips():

    if not os.path.exists(IPS_FILE):
        raise FileNotFoundError(
            f"File not found: {IPS_FILE}"
        )

    ips = []

    with open(
        IPS_FILE,
        "r",
        encoding="utf-8"
    ) as f:

        for line_number, line in enumerate(
            f,
            start=1
        ):

            ip = line.strip()

            if not ip:
                continue

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(
                    f"[WARNING] Invalid IP on line {line_number}: {ip}"
                )
                continue

            ips.append(ip)

    return ips


def load_existing():

    if not os.path.exists(JSON_FILE):
        return []

    try:

        with open(
            JSON_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if isinstance(data, list):
            return data

    except Exception as e:

        print(
            "[WARNING] Could not read existing JSON:",
            e
        )

    return []


def main():

    ips = load_ips()

    existing = load_existing()

    # IP های قبلی را نگه می‌داریم
    by_ip = {}

    for item in existing:

        if not isinstance(item, dict):
            continue

        ip = str(
            item.get("ip_address", "")
        ).strip()

        if ip:
            by_ip[ip] = item

    added = 0
    already_exists = 0

    for ip in ips:

        if ip in by_ip:

            already_exists += 1
            continue

        # فقط اطلاعات پایه
        # اطلاعات هر آنتن بعداً جداگانه تکمیل می‌شود

        by_ip[ip] = {
            "ip_address": ip,

            "device_type": "",
            "hostname": "",
            "vendor": "",
            "model": "",
            "firmware_version": "",
            "serial_number": "",
            "mac_address": "",
            "uptime": "",

            "ssid": "",
            "frequency": "",
            "tx_power": "",
            "rx_power": "",
            "signal_strength": "",
            "channel": "",
            "bandwidth": "",
            "mode": "",
            "noise_floor": "",
            "ccq": "",

            "antenna_gain": "",
            "polarization": "",
            "capacity": "",

            "latitude": "",
            "longitude": "",
            "province": "",
            "city": "",

            "scan_status": "success",
            "manual_device": True
        }

        added += 1

    result = list(
        by_ip.values()
    )

    with open(
        JSON_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            result,
            f,
            ensure_ascii=False,
            indent=2
        )

    print()
    print("================================")
    print("Manual IP import completed")
    print("================================")
    print(f"IP های داخل فایل: {len(ips)}")
    print(f"IP جدید اضافه شد: {added}")
    print(f"IP قبلاً وجود داشت: {already_exists}")
    print(f"مجموع Manual IP ها: {len(result)}")
    print("================================")


if __name__ == "__main__":
    main()
