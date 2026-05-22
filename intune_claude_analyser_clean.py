"""
Intune AI Compliance Analyser with Excel Output
Uses Federated Identity OIDC No Client Secret Required
Author: Amit Bahuguna
GitHub: github.com/Amitcicd
"""

import requests
import anthropic
import os
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
import openpyxl
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side


# CONFIGURATION
TENANT_ID  = os.environ.get("TENANT_ID", "your-tenant-id")
CLIENT_ID  = os.environ.get("CLIENT_ID", "your-app-client-id")
CLAUDE_API = os.environ.get("CLAUDE_API_KEY", "your-claude-api-key")

# COLORS FOR EXCEL
GREEN  = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
RED    = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
YELLOW = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
BLUE   = PatternFill(start_color="9DC3E6", end_color="9DC3E6", fill_type="solid")
HEADER = PatternFill(start_color="2E75B6", end_color="2E75B6", fill_type="solid")

BOLD_WHITE = Font(bold=True, color="FFFFFF", size=11)
BOLD_BLACK = Font(bold=True, color="000000", size=11)
NORMAL     = Font(color="000000", size=10)

THIN_BORDER = Border(
    left=Side(style="thin"),
    right=Side(style="thin"),
    top=Side(style="thin"),
    bottom=Side(style="thin")
)


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


def get_all_devices():
    headers = get_headers()
    url = (
        "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
        "?$select=managementAgent,ownerType,complianceState,"
        "operatingSystem,osVersion,userPrincipalName,lastSyncDateTime,"
        "isEncrypted,enrolledDateTime"
    )
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("value", [])


def get_noncompliant_devices(devices):
    return [d for d in devices if d.get("complianceState") == "noncompliant"]


def get_stale_devices(devices, days=30):
    cutoff = datetime.utcnow() - timedelta(days=days)
    stale = []
    for d in devices:
        last_sync = d.get("lastSyncDateTime", "")
        if last_sync:
            try:
                sync_date = datetime.strptime(last_sync[:19], "%Y-%m-%dT%H:%M:%S")
                if sync_date < cutoff:
                    stale.append(d)
            except Exception:
                pass
    return stale


def get_unencrypted_devices(devices):
    return [
        d for d in devices
        if d.get("operatingSystem") == "Windows"
        and not d.get("isEncrypted", True)
    ]


def format_date(date_str):
    if not date_str:
        return "Unknown"
    try:
        dt = datetime.strptime(date_str[:19], "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return date_str


def build_device_summary(devices):
    lines = []
    for d in devices:
        line = (
            "Managed By: " + str(d.get("managementAgent", "Unknown")) +
            " | Ownership: " + str(d.get("ownerType", "Unknown")) +
            " | Compliance: " + str(d.get("complianceState", "Unknown")) +
            " | OS: " + str(d.get("operatingSystem", "Unknown")) +
            " | Version: " + str(d.get("osVersion", "Unknown")) +
            " | User: " + str(d.get("userPrincipalName", "Unknown")) +
            " | Last Check-in: " + format_date(d.get("lastSyncDateTime", ""))
        )
        lines.append(line)
    return "\n".join(lines)


def analyse_with_claude(data_type, devices):
    if not devices:
        return "No issues found."

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
            "3. Specific remediation steps\n"
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
            "4. Recommendations"
        )

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )
    return message.content[0].text


def create_excel_report(devices, analyses):
    wb = openpyxl.Workbook()

    # ── SHEET 1: ALL DEVICES ──
    ws1 = wb.active
    ws1.title = "All Devices"

    # Title row
    ws1.merge_cells("A1:H1")
    ws1["A1"] = "INTUNE DEVICE COMPLIANCE REPORT - " + datetime.utcnow().strftime("%d/%m/%Y %H:%M UTC")
    ws1["A1"].font = Font(bold=True, color="FFFFFF", size=13)
    ws1["A1"].fill = HEADER
    ws1["A1"].alignment = Alignment(horizontal="center")

    # Header row
    headers = [
        "Managed By", "Ownership", "Compliance",
        "OS", "OS Version", "Primary User UPN",
        "Last Check-in", "Encrypted"
    ]
    for col, header in enumerate(headers, 1):
        cell = ws1.cell(row=2, column=col, value=header)
        cell.font = BOLD_WHITE
        cell.fill = HEADER
        cell.alignment = Alignment(horizontal="center")
        cell.border = THIN_BORDER

    # Device rows
    for row, d in enumerate(devices, 3):
        compliance = d.get("complianceState", "Unknown")
        encrypted  = d.get("isEncrypted", True)

        values = [
            d.get("managementAgent", "Unknown"),
            d.get("ownerType", "Unknown"),
            compliance,
            d.get("operatingSystem", "Unknown"),
            d.get("osVersion", "Unknown"),
            d.get("userPrincipalName", "Unknown"),
            format_date(d.get("lastSyncDateTime", "")),
            "Yes" if encrypted else "No"
        ]

        for col, value in enumerate(values, 1):
            cell = ws1.cell(row=row, column=col, value=value)
            cell.font = NORMAL
            cell.border = THIN_BORDER
            cell.alignment = Alignment(horizontal="left")

            # Color compliance column
            if col == 3:
                if compliance == "compliant":
                    cell.fill = GREEN
                elif compliance == "noncompliant":
                    cell.fill = RED
                else:
                    cell.fill = YELLOW

            # Color encrypted column
            if col == 8:
                if not encrypted and d.get("operatingSystem") == "Windows":
                    cell.fill = RED
                else:
                    cell.fill = GREEN

    # Auto column width
    for col in ws1.columns:
        max_len = 0
        for cell in col:
            try:
                if cell.value:
                    max_len = max(max_len, len(str(cell.value)))
            except Exception:
                pass
        ws1.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)

    # ── SHEET 2: NON-COMPLIANT ──
    ws2 = wb.create_sheet("Non-Compliant")
    ws2["A1"] = "NON-COMPLIANT DEVICES ANALYSIS"
    ws2["A1"].font = Font(bold=True, color="FFFFFF", size=13)
    ws2["A1"].fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
    ws2.merge_cells("A1:H1")
    ws2["A1"].alignment = Alignment(horizontal="center")

    noncompliant = [d for d in devices if d.get("complianceState") == "noncompliant"]
    if noncompliant:
        headers2 = ["Managed By", "Ownership", "OS", "OS Version", "Primary User UPN", "Last Check-in"]
        for col, header in enumerate(headers2, 1):
            cell = ws2.cell(row=2, column=col, value=header)
            cell.font = BOLD_WHITE
            cell.fill = PatternFill(start_color="C00000", end_color="C00000", fill_type="solid")
            cell.border = THIN_BORDER
            cell.alignment = Alignment(horizontal="center")

        for row, d in enumerate(noncompliant, 3):
            values = [
                d.get("managementAgent", "Unknown"),
                d.get("ownerType", "Unknown"),
                d.get("operatingSystem", "Unknown"),
                d.get("osVersion", "Unknown"),
                d.get("userPrincipalName", "Unknown"),
                format_date(d.get("lastSyncDateTime", ""))
            ]
            for col, value in enumerate(values, 1):
                cell = ws2.cell(row=row, column=col, value=value)
                cell.font = NORMAL
                cell.fill = RED
                cell.border = THIN_BORDER

        # AI Analysis
        analysis_row = len(noncompliant) + 4
        ws2.cell(row=analysis_row, column=1, value="AI ANALYSIS AND RECOMMENDATIONS")
        ws2.cell(row=analysis_row, column=1).font = BOLD_BLACK
        ws2.cell(row=analysis_row + 1, column=1, value=analyses.get("noncompliant", "No analysis available"))
        ws2.cell(row=analysis_row + 1, column=1).alignment = Alignment(wrap_text=True)
        ws2.merge_cells(
            start_row=analysis_row + 1, start_column=1,
            end_row=analysis_row + 20, end_column=6
        )
    else:
        ws2["A2"] = "All devices are compliant!"
        ws2["A2"].font = Font(bold=True, color="00B050", size=12)

    # Auto width sheet 2
    for col in ws2.columns:
        max_len = 0
        for cell in col:
            try:
                if cell.value:
                    max_len = max(max_len, len(str(cell.value)))
            except Exception:
                pass
        ws2.column_dimensions[col[0].column_letter].width = min(max_len + 4, 40)

    # ── SHEET 3: SUMMARY ──
    ws3 = wb.create_sheet("Summary")
    ws3["A1"] = "COMPLIANCE SUMMARY"
    ws3["A1"].font = Font(bold=True, color="FFFFFF", size=13)
    ws3["A1"].fill = HEADER
    ws3.merge_cells("A1:C1")
    ws3["A1"].alignment = Alignment(horizontal="center")

    total       = len(devices)
    compliant   = len([d for d in devices if d.get("complianceState") == "compliant"])
    noncompliant_count = len([d for d in devices if d.get("complianceState") == "noncompliant"])
    unencrypted = len([d for d in devices if d.get("operatingSystem") == "Windows" and not d.get("isEncrypted", True)])
    stale_count = len(get_stale_devices(devices))

    summary_data = [
        ("Total Devices", total, ""),
        ("Compliant", compliant, str(round(compliant/total*100 if total else 0, 1)) + "%"),
        ("Non-Compliant", noncompliant_count, str(round(noncompliant_count/total*100 if total else 0, 1)) + "%"),
        ("Unencrypted Windows", unencrypted, "Needs attention"),
        ("Stale Devices (30d)", stale_count, "Review recommended"),
    ]

    ws3.cell(row=2, column=1, value="Metric").font = BOLD_BLACK
    ws3.cell(row=2, column=2, value="Count").font = BOLD_BLACK
    ws3.cell(row=2, column=3, value="Details").font = BOLD_BLACK

    for row, (metric, count, detail) in enumerate(summary_data, 3):
        ws3.cell(row=row, column=1, value=metric).border = THIN_BORDER
        ws3.cell(row=row, column=2, value=count).border = THIN_BORDER
        ws3.cell(row=row, column=3, value=detail).border = THIN_BORDER

        if metric == "Compliant":
            ws3.cell(row=row, column=2).fill = GREEN
        elif metric in ("Non-Compliant", "Unencrypted Windows"):
            ws3.cell(row=row, column=2).fill = RED
        elif metric == "Stale Devices (30d)":
            ws3.cell(row=row, column=2).fill = YELLOW

    for col in ws3.columns:
        ws3.column_dimensions[col[0].column_letter].width = 30

    # Save
    filename = "intune_report_" + datetime.utcnow().strftime("%Y%m%d_%H%M") + ".xlsx"
    wb.save(filename)
    return filename


def main():
    print("Authenticating with federated identity...")

    print("Fetching all devices from Intune...")
    devices = get_all_devices()
    print("Found " + str(len(devices)) + " total devices")

    noncompliant = get_noncompliant_devices(devices)
    stale        = get_stale_devices(devices)
    unencrypted  = get_unencrypted_devices(devices)

    print("Running AI analysis...")
    analyses = {}

    if noncompliant:
        print("Analysing " + str(len(noncompliant)) + " non-compliant devices...")
        analyses["noncompliant"] = analyse_with_claude("noncompliant", noncompliant)
    else:
        analyses["noncompliant"] = "All devices are compliant!"

    if stale:
        print("Analysing " + str(len(stale)) + " stale devices...")
        analyses["stale"] = analyse_with_claude("stale", stale)
    else:
        analyses["stale"] = "All devices synced recently!"

    if unencrypted:
        print("Analysing " + str(len(unencrypted)) + " unencrypted devices...")
        analyses["bitlocker"] = analyse_with_claude("bitlocker", unencrypted)
    else:
        analyses["bitlocker"] = "All Windows devices are encrypted!"

    print("Generating Excel report...")
    filename = create_excel_report(devices, analyses)
    print("Report saved to: " + filename)

    print("\nSUMMARY:")
    print("Total devices: " + str(len(devices)))
    print("Non-compliant: " + str(len(noncompliant)))
    print("Stale devices: " + str(len(stale)))
    print("Unencrypted:   " + str(len(unencrypted)))


if __name__ == "__main__":
    main()
