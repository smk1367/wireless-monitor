#!/usr/bin/env python3

import json
import os


BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

FILE = os.path.join(
    BASE_DIR,
    "manual_devices.json"
)


def get_manual_devices():

    if not os.path.exists(FILE):
        return []

    try:

        with open(
            FILE,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        if not isinstance(data, list):
            return []

        result = []

        for item in data:

            if not isinstance(item, dict):
                continue

            ip = str(
                item.get("ip_address", "")
            ).strip()

            if not ip:
                continue

            # -----------------------------------------
            # تبدیل نام فیلدهای Manual به فیلدهای
            # مورد استفاده Dashboard
            # -----------------------------------------

            device = dict(item)

            device["ip_address"] = ip

            device["hostname"] = (
                item.get("hostname")
                or item.get("device_name")
                or ""
            )

            device["tx_power"] = (
                item.get("tx_power")
                or item.get("power")
                or ""
            )

            device["signal_strength"] = (
                item.get("signal_strength")
                or item.get("signal")
                or ""
            )

            device["noise_floor"] = (
                item.get("noise_floor")
                or item.get("noise")
                or ""
            )

            device["scan_status"] = (
                item.get("scan_status")
                or item.get("status")
                or "success"
            )

            device["device_type"] = (
                item.get("device_type")
                or "Manual"
            )

            device["vendor"] = (
                item.get("vendor")
                or ""
            )

            device["mac_address"] = (
                item.get("mac_address")
                or item.get("mac")
                or ""
            )

            device["channel"] = (
                item.get("channel")
                or ""
            )

            device["bandwidth"] = (
                item.get("bandwidth")
                or ""
            )

            device["mode"] = (
                item.get("mode")
                or ""
            )

            device["frequency"] = (
                item.get("frequency")
                or ""
            )

            device["rx_power"] = (
                item.get("rx_power")
                or ""
            )

            device["ccq"] = (
                item.get("ccq")
                or ""
            )

            device["model"] = (
                item.get("model")
                or ""
            )

            device["firmware_version"] = (
                item.get("firmware_version")
                or ""
            )

            device["serial_number"] = (
                item.get("serial_number")
                or ""
            )

            device["uptime"] = (
                item.get("uptime")
                or ""
            )

            device["antenna_gain"] = (
                item.get("antenna_gain")
                or ""
            )

            device["polarization"] = (
                item.get("polarization")
                or ""
            )

            device["capacity"] = (
                item.get("capacity")
                or ""
            )

            device["latitude"] = (
                item.get("latitude")
                or ""
            )

            device["longitude"] = (
                item.get("longitude")
                or ""
            )

            device["province"] = (
                item.get("province")
                or ""
            )

            device["city"] = (
                item.get("city")
                or ""
            )

            device["manual_device"] = True

            result.append(device)

        return result

    except Exception as e:

        print(
            "[MANUAL DEVICES] ERROR:",
            e
        )

        return []


def get_manual_device(ip):

    ip = str(ip).strip()

    devices = get_manual_devices()

    for device in devices:

        if device.get("ip_address") == ip:
            return device

    return None
