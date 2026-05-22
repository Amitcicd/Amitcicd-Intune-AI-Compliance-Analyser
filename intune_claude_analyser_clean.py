"""
Intune AI Compliance Analyser
Uses Federated Identity OIDC No Client Secret Required
Author: Amit Bahuguna
GitHub: github.com/Amitcicd
"""

import requests
import anthropic
import os
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential

# CONFIGURATION
TENANT_ID  = os.environ.get("TENANT_ID", "78ca8843-c58b-4aca-824a-9d987a027867")
CLIENT_ID  = os.environ.get("CLIENT_ID", "edd72459-8643-4257-a125-e649c9e16b85")
CLAUDE_API = os.environ.get("CLAUDE_API_KEY", "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")


def get_token():
    credential = DefaultAzureCredential(
        managed_identity_client_id=CLIENT_ID
    )
    token = credential.get_token(
        "https://graph.microsoft.com/.default"
    )
    return token.token


def get_headers():
    token = get_token()
    return {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json"
    }


def get_noncompliant_devices():
    headers = get_headers()
    url = (
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        "?$filter=complianceState eq 'noncompliant'"
        "&$select=deviceName,operatingSystem,userPrincipalName,"
        "complianceState,lastSyncDateTime,osVersion"
    )
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("value", [])


def get_stale_devices(days=30):
    headers = get_headers()
    cutoff = datetime.utcnow() - timedelta(days=days)
    date_filter = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        "?$filter=lastSyncDateTime le " + date_filter +
        "&$select=deviceName,userPrincipalName,lastSyncDateTime,operatingSystem"
    )
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("value", [])


def get_bitlocker_status():
    headers = get_headers()
    url = (
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        "?$filter=operatingSystem eq 'Windows'"
        "&$select=deviceName,userPrincipalName,isEncrypted,complianceState"
    )
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    devices = response.json().get("value", [])
    return [d for d in devices if not d.get("isEncrypted", True)]


def build_device_summary(devices):
    lines = []
    for d in devices:
        line = (
            "Device: " + d.get("deviceName", "Unknown") +
            " | OS: " + d.get("operatingSystem", "Unknown") +
            " | User: " + d.get("userPrincipalName", "Unknown") +
            " | Last Sync: " + d.get("lastSyncDateTime", "Unknown")
        )
        lines.append(line)
    return "\n".join(lines)


def analyse_with_claude(data_type, devices):
    client = anthropic.Anthropic(api_key=CLAUDE_API)
    device_summary = build_device_summary(devices)

    if data_type == "noncompliant":
        prompt = (
            "You are a Microsoft Intune expert.\n"
            "Analyse these non-compliant devices and provide remediation:\n\n"
            + device_summary +
            "\n\nProvide:\n"
            "1. Common compliance failure patterns\n"
            "2. Priority order for remediation\n"
            "3. Specific remediation steps for each issue\n"
            "4. Devices needing immediate attention"
        )
    elif data_type == "stale":
        prompt = (
            "You are a Microsoft Intune expert.\n"
            "Analyse these stale devices not synced recently:\n\n"
            + device_summary +
            "\n\nProvide:\n"
            "1. Likely reasons for sync failure\n"
            "2. Steps to force sync\n"
            "3. Devices to consider for retirement\n"
            "4. Risk assessment"
        )
    else:
        prompt = (
            "You are a Microsoft Intune expert.\n"
            "Analyse these unencrypted Windows devices:\n\n"
            + device_summary +
            "\n\nProvide:\n"
            "1. Risk level for each device\n"
            "2. Steps to enable BitLocker via Intune\n"
            "3. Prerequisites that may block encryption\n"
            "4. Compliance policy recommendations"
        )

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


def generate_report(results):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    report = "INTUNE AI COMPLIANCE REPORT\n"
    report += "Generated: " + timestamp + "\n\n"
    for section, content in results.items():
        report += "\n" + "=" * 60 + "\n"
        report += section.upper() + "\n"
        report += "=" * 60 + "\n"
        report += content + "\n"
    return report


def main():
    print("Authenticating with federated identity...")
    results = {}

    print("Fetching non-compliant devices...")
    noncompliant = get_noncompliant_devices()
    if noncompliant:
        print("Found " + str(len(noncompliant)) + " non-compliant devices")
        results["Non-Compliant Devices Analysis"] = analyse_with_claude(
            "noncompliant", noncompliant
        )
    else:
        results["Non-Compliant Devices"] = "All devices are compliant!"

    print("Fetching stale devices...")
    stale = get_stale_devices(days=30)
    if stale:
        print("Found " + str(len(stale)) + " stale devices")
        results["Stale Devices Analysis"] = analyse_with_claude(
            "stale", stale
        )
    else:
        results["Stale Devices"] = "All devices synced recently!"

    print("Fetching BitLocker compliance...")
    unencrypted = get_bitlocker_status()
    if unencrypted:
        print("Found " + str(len(unencrypted)) + " unencrypted devices")
        results["BitLocker Analysis"] = analyse_with_claude(
            "bitlocker", unencrypted
        )
    else:
        results["BitLocker Status"] = "All Windows devices are encrypted!"

    report = generate_report(results)
    print(report)

    filename = "intune_report_" + datetime.utcnow().strftime("%Y%m%d_%H%M") + ".txt"
    with open(filename, "w") as f:
        f.write(report)
    print("Report saved to: " + filename)


if __name__ == "__main__":
    main()
