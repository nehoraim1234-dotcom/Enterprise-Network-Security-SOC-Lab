<#
.SYNOPSIS
    Automated User Onboarding for Active Directory
.DESCRIPTION
    Standardizes user creation based on HR department data.
    Automatically assigns OUs and Security Groups.
.NOTES
    Author: Nehorai Security Labs
    Version: 4.0 (Production)
#>

# --- Configuration ---
$CsvPath = "C:\Scripts\Users.csv"
$LogPath = "C:\Logs\Onboarding_$(Get-Date -Format 'yyyyMMdd').log"
$Domain  = "siem_soc.local"

# Ensure Log Directory Exists
if (-not (Test-Path "C:\Logs")) { New-Item -Path "C:\Logs" -ItemType Directory | Out-Null }

function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Output = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Output
    
    switch ($Level) {
        "INFO"    { Write-Host $Output -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $Output -ForegroundColor Green }
        "ERROR"   { Write-Host $Output -ForegroundColor Red }
    }
}

# --- Validation ---
if (-not (Test-Path $CsvPath)) {
    Write-Log "Critical: CSV file not found at $CsvPath" "ERROR"
    Break
}

# --- Execution ---
$Users = Import-Csv $CsvPath

foreach ($User in $Users) {
    try {
        # Normalize Input Data
        $First = $User.FirstName.Trim()
        $Last  = $User.LastName.Trim()
        $Dept  = $User.Department.Trim()
        
        # Standard Naming Convention: firstname.lastname
        $SamAccountName = "$($First).$($Last)".ToLower()
        $UPN = "$SamAccountName@$Domain"
        
        # Check if user already exists
        if (Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -ErrorAction SilentlyContinue) {
            Write-Log "Skipping: $SamAccountName already exists." "INFO"
            continue
        }

        # Logic: Map Department to OU & Security Group
        switch ($Dept) {
            "IT" {
                $TargetOU = "OU=IT,OU=Corp,DC=siem_soc,DC=local"
                $Group    = "SG_IT_Admins"
            }
            "HR" {
                $TargetOU = "OU=HR,OU=Corp,DC=siem_soc,DC=local"
                $Group    = "SG_HR_Users"
            }
            Default {
                throw "Unknown Department: $Dept for user $SamAccountName"
            }
        }

        # Initial Password (Force change at next logon)
        $Password = ConvertTo-SecureString "Welcome2026!" -AsPlainText -Force

        # Define User Parameters (Splatting)
        $UserParams = @{
            Name                  = "$First $Last"
            GivenName             = $First
            Surname               = $Last
            SamAccountName        = $SamAccountName
            UserPrincipalName     = $UPN
            Path                  = $TargetOU
            AccountPassword       = $Password
            Enabled               = $true
            ChangePasswordAtLogon = $true
            Department            = $Dept
            Description           = $User.Description
        }

        # Create the User
        New-ADUser @UserParams -ErrorAction Stop
        
        # Add to Security Group
        Add-ADGroupMember -Identity $Group -Members $SamAccountName -ErrorAction Stop

        Write-Log "Created: $SamAccountName | OU: $Dept | Group: $Group" "SUCCESS"

    }
    catch {
        Write-Log "Failed to process $First $Last. Error: $_" "ERROR"
    }
}