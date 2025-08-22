# Identity Audit & Analysis Project

## Overview

This project provides a PowerShell-based solution for auditing and analyzing user identities across an on-premise Active Directory (AD) and a Google Workspace environment. The primary script, `identities.ps1`, consolidates data from various sources to produce a detailed, multi-sheet Excel report that highlights security risks, synchronization discrepancies, and overall identity posture.

This tool is designed for cybersecurity analysts and IT administrators to gain a single-pane-of-glass view of their hybrid identity environment.

## Features

-   **Consolidated View:** Merges user data from Active Directory and Google Workspace into a single master list.
-   **Orphan Account Detection:** Identifies accounts that exist in one platform but not the other.
-   **Status Mismatch Analysis:** Flags accounts that are enabled in AD but suspended in Google, and vice-versa.
-   **Stale Account Reporting:** Pinpoints active accounts that have not been used for a configurable period (default: 60 days).
-   **Security Auditing:** Checks for common misconfigurations, such as Google Workspace users without 2-Step Verification (2SV) enabled.
-   **Static Tagging:** Allows for the use of manually curated lists to tag non-human/service accounts and privileged groups.
-   **Multi-Sheet Excel Reporting:** Generates a clean, actionable Excel report with a high-level dashboard and detailed worksheets for each risk category.

## Prerequisites

1.  **PowerShell:** The script is designed to run on a Windows machine with PowerShell 5.1 or later.
2.  **Active Directory Module:** The machine running the AD export script requires the Active Directory PowerShell module, which is part of the Remote Server Administration Tools (RSAT).
3.  **ImportExcel Module:** The main analysis script requires the `ImportExcel` module to generate the final report. To install it, run the following command in PowerShell:
    ```powershell
    Install-Module -Name ImportExcel -Scope CurrentUser
    ```

## How to Run

1.  **Generate Input Files:**
    * Run your modified AD export script to generate the `AD_Users_Export_....csv` file.
    * Export your Google Workspace users to generate the `User_Download_....csv` file.
    * Generate the `Groups_And_Members.csv` file by running the `Get-GroupMemberships.gs` Apps Script.
        * **To run the Apps Script:**
            1.  Navigate to `script.google.com` and create a new project.
            2.  Paste the code from `Get-GroupMemberships.gs` into the editor.
            3.  In the left-hand menu, click the `+` next to "Services".
            4.  Select the **Admin SDK API** and click "Add".
            5.  Save the project.
            6.  From the dropdown menu at the top, select the `exportGroupsAndMembers` function and click **Run**.
            7.  You will need to authorize the script with your Google Workspace administrator account.
            8.  The script will create a new Google Sheet in your "My Drive". Open this sheet, go to **File > Download > Comma Separated Values (.csv)**, and save it as `Groups_And_Members.csv`.
    * Place all three generated CSV files into the `Data/Input/` directory.

2.  **Update Reference Files (If Needed):**
    * Ensure the `Non_Human_Accounts.csv` and `Privileged_Groups.csv` files in the `Data/Reference/` directory are up-to-date. The `Privileged_Groups.csv` is derived from the group membership export.

3.  **Execute the Script:**
    * Navigate to the root of the project folder in a PowerShell terminal.
    * Run the main script:
        ```powershell
        .\identities.ps1
        ```
        
## Output

The script will generate a single Excel file named `Identity_Audit_Report_YYYY-MM-DD.xlsx` inside the `Data/` folder.

This report contains multiple worksheets:

-   **Dashboard:** A high-level summary showing the total counts for each risk category.
-   **All\_Users\_Detailed:** A master sheet containing all processed data for every identity.
-   **Risk-Specific Sheets:** A separate, pre-filtered worksheet for each identified risk category (e.g., `Stale_Accounts_60_Days`, `Google_Users_No_2SV`, `Non_Human_Accounts`, etc.), providing ready-to-use action lists.
