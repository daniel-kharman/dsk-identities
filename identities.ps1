# --- 1. CONFIGURATION ---
# Define the main data folder and its subfolders for input and reference files.
$SourceFolder = Join-Path -Path $PSScriptRoot -ChildPath "Data"
$InputFolder = Join-Path -Path $SourceFolder -ChildPath "Input"
$ReferenceFolder = Join-Path -Path $SourceFolder -ChildPath "Reference"


# --- 2. FILE DISCOVERY & VALIDATION ---
Write-Host "Starting file discovery..."

# Find the Active Directory export in the 'Input' folder
$ADFile = Get-ChildItem -Path $InputFolder -Filter "AD_Users_Export_*.csv"
if ($ADFile.Count -ne 1) {
    Write-Error "Error: Expected 1 AD export file matching 'AD_Users_Export_*.csv' in '$InputFolder', but found $($ADFile.Count)."
    return
}

# Find the Google Workspace export in the 'Input' folder
$GoogleFile = Get-ChildItem -Path $InputFolder -Filter "User_Download_*.csv"
if ($GoogleFile.Count -ne 1) {
    Write-Error "Error: Expected 1 Google Workspace export file matching 'User_Download_*.csv' in '$InputFolder', but found $($GoogleFile.Count)."
    return
}

# Find the (optional) reference files in the 'Reference' folder
$NonHumanFile = Join-Path $ReferenceFolder "Non_Human_Accounts.csv"
$NonHumanFileExists = Test-Path $NonHumanFile

$PrivilegedGroupsFile = Join-Path $ReferenceFolder "Privileged_Groups.csv"
$PrivilegedGroupsFileExists = Test-Path $PrivilegedGroupsFile

$GroupsAndMembersFile = Join-Path $ReferenceFolder "Groups_And_Members.csv"
$GroupsAndMembersFileExists = Test-Path $GroupsAndMembersFile

# Confirm to the user which files are being processed
Write-Host "Files found successfully:"
Write-Host "  - Active Directory: $($ADFile.Name)"
Write-Host "  - Google Workspace: $($GoogleFile.Name)"
if ($NonHumanFileExists) {
    Write-Host "  - Non-Human Accounts: $(Split-Path $NonHumanFile -Leaf)"
}
if ($PrivilegedGroupsFileExists) {
    Write-Host "  - Privileged Groups: $(Split-Path $PrivilegedGroupsFile -Leaf)"
}
if ($GroupsAndMembersFileExists) {
    Write-Host "  - Group Memberships: $(Split-Path $GroupsAndMembersFile -Leaf)"
}
Write-Host ""


# --- 3. DATA IMPORT & PREPARATION ---
Write-Host "Importing and preparing data..."

# Import the CSV data from the discovered files
$ADDataRaw = Import-Csv -Path $ADFile.FullName
$GoogleData = Import-Csv -Path $GoogleFile.FullName

# Define a list of well-known default/service accounts to exclude from the report.
$ExcludeList = @(
    'Guest',
    'krbtgt',
    'ASPNET',
    'IUSR_SERVER',
    'IUSR_EXCHANGE',
    'Mobile User Tmpl',
    'User Tmpl',
    'SUPPORT_388945a0',
    'IWAM_SERVER',
    'IWAM_EXCHANGE',
    'Power User Tmpl',
    'Administrator Tmpl'
)

# Filter the raw AD data to remove the excluded accounts based on their SamAccountName
$ADData = $ADDataRaw | Where-Object { $_.SamAccountName -notin $ExcludeList }

# Create Hash Tables for fast, efficient lookups, keyed by the user's email address.
$ADHashTable = @{}
$GoogleHashTable = @{}
$NonHumanHashTable = @{}

$ADData.ForEach({
    # The key is converted to lower case to ensure case-insensitive matching
    $key = $_.EmailAddress.ToLower()
    if (($key) -and (-not $ADHashTable.ContainsKey($key))) {
        $ADHashTable.Add($key, $_)
    }
})

$GoogleData.ForEach({
    # The key is converted to lower case to ensure case-insensitive matching
    $key = $_.'Email Address [Required]'.ToLower()
    if (($key) -and (-not $GoogleHashTable.ContainsKey($key))) {
        $GoogleHashTable.Add($key, $_)
    }
})

# If the non-human accounts file exists, import it and create a hash table
if ($NonHumanFileExists) {
    try {
        # Import the CSV, assuming the header is 'EmailAddress' as confirmed.
        $NonHumanData = Import-Csv -Path $NonHumanFile
        if ($NonHumanData) {
            $NonHumanData.ForEach({
                $key = $_.EmailAddress.ToLower().Trim()
                if (($key) -and (-not $NonHumanHashTable.ContainsKey($key))) {
                    $NonHumanHashTable.Add($key, $true)
                }
            })
        }
    }
    catch {
        Write-Warning "Could not process the Non_Human_Accounts.csv file. It may be empty or have an unexpected header. Ensure the first line is 'EmailAddress'."
    }
}

# Import group data if the files exist
$PrivilegedMemberCountHashTable = @{}
if ($PrivilegedGroupsFileExists -and $GroupsAndMembersFileExists) {
    try {
        $PrivilegedGroupsData = Import-Csv -Path $PrivilegedGroupsFile
        $GroupsAndMembersData = Import-Csv -Path $GroupsAndMembersFile

        # Create a hash table of just the privileged group emails for fast lookups
        $PrivilegedGroupsHashTable = @{}
        $PrivilegedGroupsData | Where-Object { ([string]$_.Privileged).ToLower() -eq 'yes' } | ForEach-Object {
            $key = $_.'Group Email'.ToLower()
            if (-not $PrivilegedGroupsHashTable.ContainsKey($key)) {
                $PrivilegedGroupsHashTable.Add($key, $true)
            }
        }

        # Count privileged group memberships for each user
        $GroupsAndMembersData | Where-Object { $_.'Member Type' -eq 'USER' } | ForEach-Object {
            $groupEmail = $_.'Group Email'.ToLower()
            if ($PrivilegedGroupsHashTable.ContainsKey($groupEmail)) {
                $memberEmail = $_.'Member Email'.ToLower()
                if ($PrivilegedMemberCountHashTable.ContainsKey($memberEmail)) {
                    $PrivilegedMemberCountHashTable[$memberEmail]++
                } else {
                    $PrivilegedMemberCountHashTable[$memberEmail] = 1
                }
            }
        }
    }
    catch {
        Write-Warning "Could not process the group membership files."
    }
}


Write-Host "Data imported successfully."
Write-Host "  - $($ADDataRaw.Count) total records loaded from AD, $($ADData.Count) after filtering."
Write-Host "  - $($GoogleHashTable.Count) unique records loaded from Google Workspace."
if ($NonHumanFileExists) {
    Write-Host "  - $($NonHumanHashTable.Count) unique records loaded from Non-Human Accounts list."
}
if ($PrivilegedGroupsFileExists) {
    Write-Host "  - $($PrivilegedMemberCountHashTable.Keys.Count) users found in privileged groups."
}
Write-Host ""


# --- 4. DATA PROCESSING ---
# Initialize a .NET ArrayList for better performance when adding objects in a loop.
$FinalReportObjects = [System.Collections.ArrayList]::new()
Write-Host "Processing and consolidating identity data..."

# STAGE 1: Process all users that can be matched by email address.
$AllEmails = ($ADData.EmailAddress + $GoogleData.'Email Address [Required]') | ForEach-Object { $_.ToLower() } | Sort-Object -Unique

foreach ($Email in $AllEmails) {
    if (-not $Email) { continue } # Skip any blank entries

    # Check for the user's existence in each system using our hash tables
    $ADRecord = $ADHashTable[$Email]
    $GoogleRecord = $GoogleHashTable[$Email]

    # --- Safely parse dates and other attributes ---
    $adEnabled = if ($ADRecord) { ([string]$ADRecord.Enabled).ToLower() -eq 'true' } else { $null }
    $adIsGCDS_Member = if ($ADRecord) { ([string]$ADRecord.ismemberofgcdsusersync).ToLower() -eq 'true' } else { $null }
    $googleActive = if ($GoogleRecord) { ([string]$GoogleRecord.'Status [read only]').ToLower() -eq 'active' } else { $null }
    $google2SVEnforced = if ($GoogleRecord) { ([string]$GoogleRecord.'2sv enforced [read only]').ToLower() -eq 'true' } else { $null }
    $google2SVEnrolled = if ($GoogleRecord) { ([string]$GoogleRecord.'2sv enrolled [read only]').ToLower() -eq 'true' } else { $null }
    $googleOU = if ($GoogleRecord) { $GoogleRecord.'Org Unit Path [Required]' } else { $null }
    $isNonHuman = $NonHumanHashTable.ContainsKey($Email)
    $privilegedGroupCount = if ($PrivilegedMemberCountHashTable.ContainsKey($Email)) { $PrivilegedMemberCountHashTable[$Email] } else { 0 }
    
    # Parse the AD OU from the Canonical Name
    $adOU = $null
    if ($ADRecord.CanonicalName) {
        $parts = $ADRecord.CanonicalName.Split('/')
        if ($parts.Count -gt 2) {
            $ouPath = $parts[1..($parts.Count - 2)] -join '/'
            $adOU = $ouPath
        }
    }

    # Parse AD LastLogonDate. It's already in a standard format from the export script.
    $adLastLogon = if ($ADRecord.LastLogonDate) { [datetime]$ADRecord.LastLogonDate } else { $null }

    # Safely parse Google Last Sign In date using the specific format 'yyyy/MM/dd HH:mm:ss'
    $googleLastSignIn = $null
    if ($GoogleRecord.'Last Sign In [READ ONLY]' -and $GoogleRecord.'Last Sign In [READ ONLY]' -notmatch "Never") {
        try {
            $googleLastSignIn = [datetime]::ParseExact($GoogleRecord.'Last Sign In [READ ONLY]', 'yyyy/MM/dd HH:mm:ss', $null)
        } catch {
            Write-Warning "Could not parse date '$($GoogleRecord.'Last Sign In [READ ONLY]')' for user $($Email)."
        }
    }

    # Calculate the discrepancy in days between the two last logon dates
    $logonDiscrepancyDays = $null
    if ($adLastLogon -and $googleLastSignIn) {
        $timeSpan = $adLastLogon - $googleLastSignIn
        $logonDiscrepancyDays = [System.Math]::Abs($timeSpan.Days)
    }

    # Create a new object to hold our findings for this identity
    $object = [PSCustomObject]@{
        EmailAddress         = $Email
        Is_NonHuman_Account  = $isNonHuman
        MissingEmailaddress  = $false # This user was matched by email
        AD_IsGCDS_Member     = $adIsGCDS_Member
        Privileged_Group_Count = $privilegedGroupCount
        InActiveDirectory    = if ($ADRecord) { $true } else { $false }
        InGoogleWorkspace    = if ($GoogleRecord) { $true } else { $false }
        AD_Enabled           = $adEnabled
        AD_OU                = $adOU
        Google_Active        = $googleActive
        Google_2SV_Enforced  = $google2SVEnforced
        Google_2SV_Enrolled  = $google2SVEnrolled
        Google_OU            = $googleOU
        AD_LastLogon         = $adLastLogon
        Google_LastSignIn    = $googleLastSignIn
        LogonDiscrepancyDays = $logonDiscrepancyDays
    }

    # --- Add calculated properties for analysis ---
    $syncStatus = "Unknown"
    if ($object.InActiveDirectory -and $object.InGoogleWorkspace) {
        $syncStatus = "Exists in Both"
    }
    elseif ($object.InActiveDirectory -and -not $object.InGoogleWorkspace) {
        $syncStatus = "Exists Only in AD"
    }
    elseif (-not $object.InActiveDirectory -and $object.InGoogleWorkspace) {
        $syncStatus = "Exists Only in Google"
    }
    $object | Add-Member -NotePropertyName SyncStatus -NotePropertyValue $syncStatus

    $statusMismatch = $null
    if ($syncStatus -eq "Exists in Both") {
        $statusMismatch = ($adEnabled -ne $googleActive)
    }
    $object | Add-Member -NotePropertyName StatusMismatch -NotePropertyValue $statusMismatch

    # Determine the true last activity date across both platforms
    $lastSeen = ($adLastLogon, $googleLastSignIn | Where-Object { $_ } | Measure-Object -Maximum).Maximum
    $daysInactive = if ($lastSeen) { ((Get-Date) - $lastSeen).Days } else { $null }
    $object | Add-Member -NotePropertyName DaysSinceLastActivity -NotePropertyValue $daysInactive
    
    # Add the final object to our collection
    [void]$FinalReportObjects.Add($object)
}

# STAGE 2: Find and process AD users who were missed because they have no email address.
$ADUsersWithoutEmail = $ADData | Where-Object { -not $_.EmailAddress }
Write-Host "Found $($ADUsersWithoutEmail.Count) AD users without an email address. Adding them to the report..."

foreach ($ADRecord in $ADUsersWithoutEmail) {
    # Since there's no email, we use the UPN as the primary identifier.
    $identifier = $ADRecord.UserPrincipalName

    # --- Safely parse AD-specific attributes ---
    $adEnabled = ([string]$ADRecord.Enabled).ToLower() -eq 'true'
    $adIsGCDS_Member = ([string]$ADRecord.ismemberofgcdsusersync).ToLower() -eq 'true'
    $adLastLogon = if ($ADRecord.LastLogonDate) { [datetime]$ADRecord.LastLogonDate } else { $null }
    $isNonHuman = $NonHumanHashTable.ContainsKey($identifier.ToLower())
    $privilegedGroupCount = if ($PrivilegedMemberCountHashTable.ContainsKey($identifier.ToLower())) { $PrivilegedMemberCountHashTable[$identifier.ToLower()] } else { 0 }
    
    # Parse the AD OU from the Canonical Name
    $adOU = $null
    if ($ADRecord.CanonicalName) {
        $parts = $ADRecord.CanonicalName.Split('/')
        if ($parts.Count -gt 2) {
            $ouPath = $parts[1..($parts.Count - 2)] -join '/'
            $adOU = $ouPath
        }
    }

    # Create the object for this AD-only user
    $object = [PSCustomObject]@{
        EmailAddress         = $identifier # Using UPN in this column
        Is_NonHuman_Account  = $isNonHuman
        MissingEmailaddress  = $true # This user was processed via the fallback
        AD_IsGCDS_Member     = $adIsGCDS_Member
        Privileged_Group_Count = $privilegedGroupCount
        InActiveDirectory    = $true
        InGoogleWorkspace    = $false
        AD_Enabled           = $adEnabled
        AD_OU                = $adOU
        Google_Active        = $null
        Google_2SV_Enforced  = $null
        Google_2SV_Enrolled  = $null
        Google_OU            = $null
        AD_LastLogon         = $adLastLogon
        Google_LastSignIn    = $null
        LogonDiscrepancyDays = $null
        SyncStatus           = "Exists Only in AD"
        StatusMismatch       = $null
        DaysSinceLastActivity = if ($adLastLogon) { ((Get-Date) - $adLastLogon).Days } else { $null }
    }
    
    # Add this object to our final collection
    [void]$FinalReportObjects.Add($object)
}


Write-Host "Processing complete."
Write-Host "  - A total of $($FinalReportObjects.Count) unique identities have been processed."
Write-Host ""


# --- 5. EXPORT MULTI-SHEET REPORT ---
$FileDate = Get-Date -Format "yyyy-MM-dd"
$OutputFileName = "Identity_Audit_Report_$($FileDate).xlsx"
$OutputPath = Join-Path $SourceFolder $OutputFileName

# Check if the ImportExcel module is available
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Warning "ImportExcel module not found. Exporting to a single CSV as a fallback."
    $CsvOutputPath = $OutputPath -replace '\.xlsx$', '.csv'
    $FinalReportObjects | Export-Csv -Path $CsvOutputPath -NoTypeInformation
    return
}

Import-Module ImportExcel
Write-Host "Exporting multi-sheet Excel report to '$OutputPath'..."

# Define the risk categories and their corresponding filters
$RiskCategories = @(
    @{ Name = "AD_Only_Orphans";         Filter = { $_.SyncStatus -eq "Exists Only in AD" }; Columns = "EmailAddress", "MissingEmailaddress", "AD_IsGCDS_Member", "InActiveDirectory", "InGoogleWorkspace", "AD_Enabled", "AD_OU", "AD_LastLogon", "SyncStatus" },
    @{ Name = "Google_Only_Orphans";     Filter = { $_.SyncStatus -eq "Exists Only in Google" }; Columns = "EmailAddress", "InActiveDirectory", "InGoogleWorkspace", "Google_Active", "Google_2SV_Enforced", "Google_OU", "Google_LastSignIn", "SyncStatus" },
    @{ Name = "Status_Mismatches";       Filter = { $_.StatusMismatch -eq $true }; Columns = "EmailAddress", "AD_Enabled", "Google_Active", "AD_OU", "Google_OU", "LogonDiscrepancyDays", "SyncStatus", "StatusMismatch" },
    @{ Name = "Stale_Accounts_60_Days";  Filter = { $_.DaysSinceLastActivity -gt 60 -and ($_.AD_Enabled -or $_.Google_Active) }; Columns = "EmailAddress", "AD_Enabled", "Google_Active", "AD_OU", "Google_OU", "AD_LastLogon", "Google_LastSignIn", "DaysSinceLastActivity", "SyncStatus" },
    @{ Name = "Google_Users_No_2SV";     Filter = { $_.Google_Active -eq $true -and $_.Google_2SV_Enforced -eq $false }; Columns = "EmailAddress", "Google_Active", "Google_2SV_Enrolled", "Google_2SV_Enforced", "Google_OU", "Google_LastSignIn" },
    @{ Name = "Non_Human_Accounts";      Filter = { $_.Is_NonHuman_Account -eq $true }; Columns = "EmailAddress", "Is_NonHuman_Account", "SyncStatus", "AD_Enabled", "Google_Active" },
    @{ Name = "Users_In_Privileged_Groups"; Filter = { $_.Privileged_Group_Count -gt 0 }; Columns = "EmailAddress", "Privileged_Group_Count", "Google_Active", "Google_2SV_Enforced" }
)

# Create a summary dashboard object with counts for each category
$Dashboard = [ordered]@{}
$Dashboard["Total Identities Analyzed"] = $FinalReportObjects.Count
foreach ($Category in $RiskCategories) {
    $Dashboard[$Category.Name] = ($FinalReportObjects | Where-Object $Category.Filter).Count
}

# Add Privileged Groups count to the dashboard if the data exists
$PrivilegedGroups = $null
if ($PrivilegedGroupsData) {
    $PrivilegedGroups = $PrivilegedGroupsData | Where-Object { ([string]$_.Privileged).ToLower() -eq 'yes' }
    $Dashboard["Total_Privileged_Google_Groups"] = $PrivilegedGroups.Count
}

# Export the Dashboard as the first sheet
$Dashboard.GetEnumerator() | Select-Object @{Name="Metric"; Expression={$_.Name}}, @{Name="Count"; Expression={$_.Value}} |
    Export-Excel -Path $OutputPath -WorksheetName "Dashboard" -AutoSize -TableName "Dashboard" -TableStyle "Medium2"

# Export the main detailed data sheet
$FinalReportObjects | Export-Excel -Path $OutputPath -WorksheetName "All_Users_Detailed" -AutoSize -TableName "AllUsers" -Append

# Export a separate sheet for each risk category
foreach ($Category in $RiskCategories) {
    $Data = $FinalReportObjects | Where-Object $Category.Filter
    if ($Data) {
        $Data | Select-Object $Category.Columns |
            Export-Excel -Path $OutputPath -WorksheetName $Category.Name -AutoSize -TableName $Category.Name -Append
    }
}

# Export the Privileged Groups sheet if data exists
if ($PrivilegedGroups) {
    $PrivilegedGroups | Select-Object 'Group Email' |
        Export-Excel -Path $OutputPath -WorksheetName "Privileged_Groups" -AutoSize -TableName "PrivilegedGroups" -Append
}

# Reopen the package to apply specific formatting
try {
    $excel = Open-ExcelPackage -Path $OutputPath
    
    # Format date columns in the main detailed sheet
    $wsDetailed = $excel.Workbook.Worksheets["All_Users_Detailed"]
    if ($wsDetailed) {
        $adLogonCol = ($wsDetailed.Cells["1:1"] | Where-Object { $_.Value -eq "AD_LastLogon" }).Start.Column
        $googleSignInCol = ($wsDetailed.Cells["1:1"] | Where-Object { $_.Value -eq "Google_LastSignIn" }).Start.Column
        if ($adLogonCol) { $wsDetailed.Column($adLogonCol).Style.Numberformat.Format = 'yyyy-MM-dd HH:mm:ss' }
        if ($googleSignInCol) { $wsDetailed.Column($googleSignInCol).Style.Numberformat.Format = 'yyyy-MM-dd HH:mm:ss' }
    }
    
    Close-ExcelPackage $excel
}
catch {
    Write-Warning "Could not apply custom date formatting to the Excel file."
}

Write-Host "--- COMPLETE ---" -ForegroundColor Green
Write-Host "The final Excel report has been saved."
