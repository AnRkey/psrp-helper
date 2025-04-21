<#
.SYNOPSIS
Configures the local machine for PowerShell Remoting over HTTPS, validates remote configurations, runs remote commands, or undoes local configuration.

.DESCRIPTION
The PSRP Helper script simplifies the process of setting up the local machine for secure PowerShell Remoting (PSRP) using HTTPS and a self-signed certificate.
It can also be used to test the PSRP HTTPS configuration of a remote machine, execute commands remotely via PSRP HTTPS, or revert the local configuration changes made by the script.

Requires administrative privileges for local setup and undo operations.

.PARAMETER Test
Switch parameter to enter Remote Validation Mode. Requires -RemoteIP and potentially -Credential.

.PARAMETER RemoteIP
Specifies the IP address or hostname of the remote machine for Validation or Command Execution modes.

.PARAMETER Credential
Specifies the user credential for connecting to the remote machine. If omitted, the script will prompt for credentials.

.PARAMETER RunCommand
Switch parameter to enter Remote Command Execution Mode. Requires -RemoteIP, -CommandToRun, and potentially -Credential.

.PARAMETER CommandToRun
Specifies the command string to execute on the remote machine in Command Execution Mode.

.PARAMETER Undo
Switch parameter to enter Undo Mode, removing the script's local HTTPS listener and firewall rule.

.PARAMETER Help
Switch parameter to display the help message and exit.

.PARAMETER Version
Switch parameter to display the script version and exit.

.EXAMPLE
.\psrp-helper.ps1
Configures the local machine for PSRP over HTTPS (Default Mode).

.EXAMPLE
.\psrp-helper.ps1 -Test -RemoteIP 192.168.1.100
Validates the PSRP HTTPS configuration on the remote machine 192.168.1.100, prompting for credentials.

.EXAMPLE
.\psrp-helper.ps1 -RunCommand -RemoteIP win10-remote -CommandToRun "Get-Process" -Credential (Get-Credential)
Runs the 'Get-Process' command on the remote machine 'win10-remote' using the provided credentials.

.EXAMPLE
.\psrp-helper.ps1 -Undo
Removes the HTTPS listener and firewall rule created by the script on the local machine.

.EXAMPLE
.\psrp-helper.ps1 -Help
Displays this help message.

.EXAMPLE
.\psrp-helper.ps1 -Version
Displays the script version.

.NOTES
Author: Gemini
Version: 1.0
Date: $(Get-Date -Format 'yyyy-MM-dd')
Requires: PowerShell 5.1 or later, Administrative privileges for local setup/undo.
Security Note: Remote validation/command execution bypasses certificate CN and CA checks by default (-SkipCNCheck, -SkipCACheck). This is suitable for self-signed certificates but implies trust in the target machine.

#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'LocalSetup')]
param(
    [Parameter(ParameterSetName = 'Test')]
    [switch]$Test,

    [Parameter(ParameterSetName = 'Test', Mandatory = $true)]
    [Parameter(ParameterSetName = 'RunCommand', Mandatory = $true)]
    [string]$RemoteIP,

    [Parameter(ParameterSetName = 'Test')]
    [Parameter(ParameterSetName = 'RunCommand')]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(ParameterSetName = 'RunCommand')]
    [switch]$RunCommand,

    [Parameter(ParameterSetName = 'RunCommand', Mandatory = $true)]
    [string]$CommandToRun,

    [Parameter(ParameterSetName = 'Undo')]
    [switch]$Undo,

    [Parameter(ParameterSetName = 'Help')]
    [switch]$Help,

    [Parameter(ParameterSetName = 'Version')]
    [switch]$Version
)

#region Global Variables and Settings
$ScriptVersion = "1.0"
$DefaultFirewallRuleName = "WINRM-HTTPS"
$ListenerTransport = "HTTPS"
$ListenerPort = 5986
$CertificateValidityDays = 365
$CertificateExpiryWarningDays = 30
#endregion

#region Helper Functions

function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SuitableLocalIPAddress {
    Write-Verbose "Attempting to find a suitable local non-loopback, non-APIPA IPv4 address..."
    $ipAddresses = Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred | Where-Object {
        $_.InterfaceAlias -notlike 'Loopback*' -and
        $_.IPAddress -notlike '169.254.*'
    }

    if ($ipAddresses.Count -eq 0) {
        Write-Error "Could not find a suitable local IPv4 address."
        return $null
    } elseif ($ipAddresses.Count -gt 1) {
        Write-Warning "Multiple suitable IP addresses found. Selecting the first one: $($ipAddresses[0].IPAddress)"
        # TODO: Potentially add logic to let the user choose or prioritize based on interface metrics
    }
    $selectedIP = $ipAddresses[0].IPAddress
    Write-Verbose "Using IP Address: $selectedIP"
    return $selectedIP
}

function Write-SetupStepStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StepName,

        [Parameter(Mandatory = $true)]
        [string]$Status, # e.g., "Success", "Skipped", "Failed", "Warning"

        [string]$Message
    )
    $statusColor = switch ($Status) {
        "Success" { "Green" }
        "Skipped" { "Yellow" }
        "Warning" { "Yellow" }
        "Failed"  { "Red" }
        default   { "White" }
    }
    Write-Host ("[{0}] {1}" -f $StepName, $Status) -ForegroundColor $statusColor
    if ($Message) {
        Write-Host ("  `- {0}" -f $Message)
    }
}

function Get-PSRPCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )
    Write-Verbose "Checking for existing certificate with CN=$IpAddress in Cert:\LocalMachine\My"
    Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -eq "CN=$IpAddress" }
}

function New-PSRPCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )
    $subject = "CN=$IpAddress"
    $notAfter = (Get-Date).AddDays($CertificateValidityDays)

    Write-Verbose "Creating new self-signed certificate: Subject='$subject', Valid until '$($notAfter.ToString('yyyy-MM-dd'))'"

    if ($PSCmdlet.ShouldProcess("LocalMachine\My", "Create self-signed certificate with Subject '$subject'")) {
        try {
            $certParams = @{
                Subject            = $subject
                CertStoreLocation  = "Cert:\LocalMachine\My"
                KeyExportPolicy    = 'Exportable' # Required for WinRM listener
                KeyAlgorithm       = 'RSA'
                KeyLength          = 2048
                HashAlgorithm      = 'SHA256'
                NotAfter           = $notAfter
                KeyUsage           = @('KeyEncipherment', 'DigitalSignature')
                TextExtension      = @('2.5.29.37={text}1.3.6.1.5.5.7.3.1') # Server Authentication EKU
                ErrorAction        = 'Stop'
                FriendlyName       = "PSRP Helper Cert ($IpAddress)"
            }
            $newCert = New-SelfSignedCertificate @certParams
            Write-Verbose "Successfully created certificate. Thumbprint: $($newCert.Thumbprint)"
            return $newCert
        }
        catch {
            Write-Error "Failed to create self-signed certificate: $_"
            return $null
        }
    } else {
        Write-Warning "Certificate creation skipped due to -WhatIf."
        return $null # Indicate skipped/not created
    }
}

function Ensure-FirewallRule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName,
        [Parameter(Mandatory = $true)]
        [int]$Port
    )
    Write-Verbose "Checking firewall rule '$RuleName' for TCP port $Port..."
    $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

    if ($rule) {
        Write-Verbose "Firewall rule '$RuleName' found."
        if (-not $rule.Enabled) {
            Write-Warning "Firewall rule '$RuleName' found but is disabled."
            if ($PSCmdlet.ShouldProcess($RuleName, "Enable Firewall Rule")) {
                 try {
                    Write-Verbose "Enabling firewall rule '$RuleName'..."
                    Set-NetFirewallRule -DisplayName $RuleName -Enabled True -ErrorAction Stop
                    Write-SetupStepStatus -StepName "Firewall Rule" -Status "Success" -Message "Rule '$RuleName' enabled."
                 } catch {
                    Write-Error "Failed to enable firewall rule '$RuleName': $_"
                    Write-SetupStepStatus -StepName "Firewall Rule" -Status "Failed" -Message "Could not enable rule '$RuleName'."
                 }
            } else {
                Write-Warning "Firewall rule enabling skipped due to -WhatIf."
                Write-SetupStepStatus -StepName "Firewall Rule" -Status "Skipped" -Message "Rule '$RuleName' exists but remains disabled (-WhatIf)."
            }
        } else {
            Write-Verbose "Firewall rule '$RuleName' is already enabled."
            Write-SetupStepStatus -StepName "Firewall Rule" -Status "Success" -Message "Rule '$RuleName' exists and is enabled."
        }
    } else {
        Write-Verbose "Firewall rule '$RuleName' not found. Creating..."
        if ($PSCmdlet.ShouldProcess("Inbound TCP Port $Port", "Create Firewall Rule '$RuleName'")) {
            try {
                New-NetFirewallRule -DisplayName $RuleName `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort $Port `
                    -Action Allow `
                    -Enabled True `
                    -ErrorAction Stop
                Write-Verbose "Successfully created firewall rule '$RuleName'."
                Write-SetupStepStatus -StepName "Firewall Rule" -Status "Success" -Message "Rule '$RuleName' created and enabled."
            }
            catch {
                Write-Error "Failed to create firewall rule '$RuleName': $_"
                 Write-SetupStepStatus -StepName "Firewall Rule" -Status "Failed" -Message "Could not create rule '$RuleName'."
            }
        } else {
            Write-Warning "Firewall rule creation skipped due to -WhatIf."
            Write-SetupStepStatus -StepName "Firewall Rule" -Status "Skipped" -Message "Rule '$RuleName' creation skipped (-WhatIf)."
        }
    }
}

function Ensure-HttpsListener {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificateThumbprint
    )
    $listenerPath = "WSMan:\localhost\Listener\*\Transport=$ListenerTransport"
    Write-Verbose "Checking for existing WinRM HTTPS listener..."
    $listener = Get-Item -Path $listenerPath -ErrorAction SilentlyContinue

    if ($listener) {
        Write-Verbose "Existing HTTPS listener found."
        $currentThumbprint = (Get-ItemProperty -Path $listener.PSPath).CertificateThumbprint
        if ($currentThumbprint -ne $CertificateThumbprint) {
            Write-Warning "Existing HTTPS listener found but uses a different certificate thumbprint ($currentThumbprint). Updating..."
            if ($PSCmdlet.ShouldProcess($listener.PSPath, "Update Listener Certificate Thumbprint to $CertificateThumbprint")) {
                try {
                    Set-Item -Path $listener.PSPath -Value $CertificateThumbprint -Force -ErrorAction Stop
                    Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Success" -Message "Listener updated with correct certificate thumbprint."
                } catch {
                     Write-Error "Failed to update listener certificate thumbprint: $_"
                     Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Failed" -Message "Could not update listener thumbprint."
                }
            } else {
                Write-Warning "Listener update skipped due to -WhatIf."
                Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Skipped" -Message "Listener update skipped (-WhatIf)."
            }
        } else {
            Write-Verbose "Existing HTTPS listener is already configured with the correct certificate thumbprint."
             Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Success" -Message "Listener already configured correctly."
        }
    } else {
        Write-Verbose "No existing HTTPS listener found. Creating..."
         if ($PSCmdlet.ShouldProcess("WSMan:\localhost\Listener", "Create HTTPS Listener with Thumbprint $CertificateThumbprint")) {
            try {
                $listenerParams = @{
                    Path                = 'WSMan:\localhost\Listener'
                    Transport           = $ListenerTransport
                    Address             = '*' # Listen on all addresses
                    CertificateThumbprint = $CertificateThumbprint
                    Force               = $true
                    ErrorAction         = 'Stop'
                }
                New-Item @listenerParams
                 Write-Verbose "Successfully created HTTPS listener."
                 Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Success" -Message "HTTPS listener created."
            } catch {
                Write-Error "Failed to create HTTPS listener: $_"
                Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Failed" -Message "Could not create listener."
            }
         } else {
             Write-Warning "Listener creation skipped due to -WhatIf."
             Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Skipped" -Message "Listener creation skipped (-WhatIf)."
         }
    }
}

function Remove-HttpsListener {
     $listenerPath = "WSMan:\localhost\Listener\*\Transport=$ListenerTransport"
     Write-Verbose "Attempting to find HTTPS listener..."
     $listener = Get-Item -Path $listenerPath -ErrorAction SilentlyContinue

     if ($listener) {
         Write-Verbose "HTTPS listener found at $($listener.PSPath)."
         if ($PSCmdlet.ShouldProcess($listener.PSPath, "Remove HTTPS Listener")) {
            try {
                Remove-Item -Path $listener.PSPath -Recurse -Force -ErrorAction Stop
                Write-Host "[Undo] Successfully removed HTTPS listener." -ForegroundColor Green
            } catch {
                Write-Error "[Undo] Failed to remove HTTPS listener: $_"
            }
         } else {
             Write-Warning "[Undo] Listener removal skipped due to -WhatIf."
         }
     } else {
         Write-Host "[Undo] No HTTPS listener found to remove." -ForegroundColor Yellow
     }
}

function Remove-FirewallRule {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )
     Write-Verbose "Attempting to find firewall rule '$RuleName'..."
     $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

     if ($rule) {
         Write-Verbose "Firewall rule '$RuleName' found."
         if ($PSCmdlet.ShouldProcess($RuleName, "Remove Firewall Rule")) {
            try {
                Remove-NetFirewallRule -DisplayName $RuleName -ErrorAction Stop
                Write-Host "[Undo] Successfully removed firewall rule '$RuleName'." -ForegroundColor Green
            } catch {
                Write-Error "[Undo] Failed to remove firewall rule '$RuleName': $_"
            }
         } else {
             Write-Warning "[Undo] Firewall rule removal skipped due to -WhatIf."
         }
     } else {
         Write-Host "[Undo] Firewall rule '$RuleName' not found to remove." -ForegroundColor Yellow
     }
}

function Show-Help {
    # Get the comment-based help content
    Get-Help $MyInvocation.MyCommand.Definition -Full | Out-String | Write-Host
}

function Show-Version {
    Write-Host "PSRP Helper Script Version: $ScriptVersion"
}

#endregion

#region Main Logic

# Handle Help and Version parameters first
if ($Help) {
    Show-Help
    exit 0
}
if ($Version) {
    Show-Version
    exit 0
}

# --- Parameter Set Logic ---
$effectiveParameterSetName = $PSCmdlet.ParameterSetName
Write-Verbose "Executing in mode: $effectiveParameterSetName"

switch ($effectiveParameterSetName) {
    'LocalSetup' {
        Write-Host "--- Starting Local PSRP HTTPS Setup ---"

        if (-not (Test-IsAdmin)) {
            Write-Error "Administrative privileges are required for local setup. Please re-run as Administrator."
            exit 1
        }

        # FR1.1: Check/Set Network Profile
        # Note: Setting network profile programmatically can be complex and disruptive.
        #       Just checking and warning for now.
        $netProfile = Get-NetConnectionProfile | Where-Object { $_.IPv4Connectivity -ne 'NoTraffic' }
        if ($netProfile.NetworkCategory -ne 'Private') {
            Write-Warning "Current network profile is '$($netProfile.NetworkCategory)'. PSRP often requires 'Private'. Manual adjustment may be needed if issues occur."
            # Consider adding -Force option to attempt setting? Requires Import-Module NetSecurity
            # if ($PSCmdlet.ShouldProcess($netProfile.Name, "Set Network Profile to Private")) { ... }
            Write-SetupStepStatus -StepName "Network Profile" -Status "Warning" -Message "Profile is '$($netProfile.NetworkCategory)', expected 'Private'."
        } else {
             Write-SetupStepStatus -StepName "Network Profile" -Status "Success" -Message "Profile is 'Private'."
        }


        # FR1.2: Enable PowerShell Remoting
        Write-Verbose "Ensuring PowerShell Remoting is enabled..."
        try {
            $remotingState = Get-PSSessionConfiguration -Name Microsoft.PowerShell -ErrorAction SilentlyContinue
            if ($remotingState.Enabled) {
                 Write-Verbose "PowerShell Remoting is already enabled."
                 Write-SetupStepStatus -StepName "PS Remoting" -Status "Success" -Message "Already enabled."
            } else {
                if ($PSCmdlet.ShouldProcess("Local Machine", "Enable PowerShell Remoting")) {
                    Enable-PSRemoting -Force -ErrorAction Stop
                    Write-Verbose "Successfully enabled PowerShell Remoting."
                    Write-SetupStepStatus -StepName "PS Remoting" -Status "Success" -Message "Enabled successfully."
                } else {
                    Write-Warning "PS Remoting enabling skipped due to -WhatIf."
                    Write-SetupStepStatus -StepName "PS Remoting" -Status "Skipped" -Message "Enabling skipped (-WhatIf)."
                    # Note: Subsequent steps might fail if remoting isn't enabled
                }
            }
        } catch {
            Write-Error "Failed to enable PowerShell Remoting: $_"
            Write-SetupStepStatus -StepName "PS Remoting" -Status "Failed" -Message "Error during enabling."
            # Decide whether to exit or continue with warnings
            # exit 1
        }

        # FR1.4: Get Local IP
        $localIp = Get-SuitableLocalIPAddress
        if (-not $localIp) {
            Write-Error "Halting setup: Could not determine a suitable local IP address."
             Write-SetupStepStatus -StepName "Local IP" -Status "Failed" -Message "Could not find suitable IP."
            exit 1
        }
         Write-SetupStepStatus -StepName "Local IP" -Status "Success" -Message "Using IP: $localIp"


        # FR1.5: Ensure Certificate
        $cert = Get-PSRPCertificate -IpAddress $localIp
        $certThumbprint = $null

        if ($cert) {
            Write-Verbose "Found existing certificate for $localIp. Thumbprint: $($cert.Thumbprint)"
            if ($cert.NotAfter -lt (Get-Date).AddDays($CertificateExpiryWarningDays)) {
                Write-Warning "Existing certificate expires soon ($($cert.NotAfter.ToString('yyyy-MM-dd')))."
                # FR1.5.2: Prompt for renewal (respect -WhatIf implicitly via ShouldProcess in New/Remove)
                # Currently, just creating a new one implicitly handles this if creation proceeds.
                # More robust would be to explicitly remove the old one first if user confirms.
                Write-Verbose "Proceeding to create a new certificate."
                $cert = $null # Force creation below
            } else {
                Write-Verbose "Existing certificate is valid."
                $certThumbprint = $cert.Thumbprint
                 Write-SetupStepStatus -StepName "Certificate" -Status "Success" -Message "Valid existing certificate found."
            }
        }

        if (-not $cert) {
             Write-Verbose "No valid certificate found or renewal needed. Attempting to create a new one..."
             $newCert = New-PSRPCertificate -IpAddress $localIp
             if ($newCert) {
                 $certThumbprint = $newCert.Thumbprint
                 Write-SetupStepStatus -StepName "Certificate" -Status "Success" -Message "New certificate created."
             } else {
                 Write-Error "Halting setup: Failed to create or obtain a certificate."
                 Write-SetupStepStatus -StepName "Certificate" -Status "Failed" -Message "Certificate creation failed or skipped (-WhatIf)."
                 exit 1
             }
        }

        # FR1.3: Ensure Firewall Rule (needs to happen before listener potentially?)
        Ensure-FirewallRule -RuleName $DefaultFirewallRuleName -Port $ListenerPort

        # FR1.6: Ensure HTTPS Listener
        if ($certThumbprint) {
            Ensure-HttpsListener -CertificateThumbprint $certThumbprint
        } else {
             Write-Error "Cannot configure listener because no certificate thumbprint was obtained."
             Write-SetupStepStatus -StepName "HTTPS Listener" -Status "Failed" -Message "Skipped due to missing certificate."
        }

        Write-Host "--- Local PSRP HTTPS Setup Finished ---"
        # FR1.8: Report overall status (can be inferred from step statuses)
        # TODO: Add a summary based on the success/failure of steps
    }
    'Test' {
        Write-Host "--- Starting Remote PSRP HTTPS Validation for $RemoteIP ---"

        # FR2.2: Get Credentials if needed
        if (-not $Credential) {
            Write-Verbose "Credential parameter not provided, prompting user."
            $Credential = Get-Credential -Message "Enter credentials for remote machine '$RemoteIP'"
            if (-not $Credential) {
                Write-Error "Credentials are required for remote validation. Exiting."
                exit 1
            }
        }

        # FR2.4: Session Options
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck

        # FR2.3: Attempt Connection
        $session = $null
        $connectionError = $null
        Write-Host "Attempting to connect to $RemoteIP on port $ListenerPort using SSL..."
        try {
            $session = New-PSSession -ComputerName $RemoteIP `
                -Port $ListenerPort `
                -Credential $Credential `
                -UseSSL `
                -SessionOption $sessionOption `
                -ErrorAction Stop
            Write-Host "[Connection Status] Connected successfully." -ForegroundColor Green
        }
        catch {
            $connectionError = $_
            Write-Host "[Connection Status] Failed to connect." -ForegroundColor Red
            Write-Error "Connection Error: $($connectionError.Exception.Message)"
        }

        # FR2.5: Perform Remote Checks if connected
        $remoteResults = @{
            "Session Established" = $false
            "Listener Configured" = "N/A"
            "Firewall Rule Present" = "N/A"
            "Firewall Rule Enabled" = "N/A"
            "Certificate Present" = "N/A"
        }

        if ($session) {
            $remoteResults["Session Established"] = $true
             Write-Host "Performing remote checks..."
            try {
                $scriptBlock = {
                    param($RuleName)

                    $results = @{
                        ListenerConfigured = $false
                        FirewallRulePresent = $false
                        FirewallRuleEnabled = $false
                        CertificatePresent = $false
                        ErrorMessage = $null
                    }
                    try {
                        # Check Listener
                        $listener = Get-Item -Path "WSMan:\localhost\Listener\*\Transport=HTTPS" -ErrorAction SilentlyContinue
                        $results.ListenerConfigured = ($null -ne $listener)

                        # Check Firewall
                        $rule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
                        if ($rule) {
                            $results.FirewallRulePresent = $true
                            $results.FirewallRuleEnabled = $rule.Enabled
                        }

                        # Check for *any* cert in LocalMachine\My (as per FR2.5)
                        $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue
                        $results.CertificatePresent = ($certs.Count -gt 0)

                    } catch {
                         $results.ErrorMessage = "Error during remote check: $($_.Exception.Message)"
                    }
                    return $results
                } # End ScriptBlock

                $remoteCheckOutput = Invoke-Command -Session $session -ScriptBlock $scriptBlock -ArgumentList $DefaultFirewallRuleName -ErrorAction Stop
                if ($remoteCheckOutput) {
                    $remoteResults["Listener Configured"] = $remoteCheckOutput.ListenerConfigured
                    $remoteResults["Firewall Rule Present"] = $remoteCheckOutput.FirewallRulePresent
                    $remoteResults["Firewall Rule Enabled"] = $remoteCheckOutput.FirewallRuleEnabled
                    $remoteResults["Certificate Present"] = $remoteCheckOutput.CertificatePresent
                    if ($remoteCheckOutput.ErrorMessage){
                         Write-Warning "Error reported from remote check script: $($remoteCheckOutput.ErrorMessage)"
                    }
                } else {
                     Write-Warning "Did not receive expected results from remote check command."
                }

            } catch {
                Write-Error "Failed to execute remote checks: $($_.Exception.Message)"
            }
        }

        # FR2.6: Display Summary Report
        Write-Host "`n--- Validation Report for $RemoteIP ---"
        Write-Host "Connection Attempt:   $(if ($session) { 'Success' } else { 'Failed' })"
        Write-Host "Session Established:  $($remoteResults['Session Established'])"
        if ($session) {
             Write-Host "Listener Configured:  $($remoteResults['Listener Configured'])"
             Write-Host "Firewall Rule Present: $($remoteResults['Firewall Rule Present'])"
             Write-Host "Firewall Rule Enabled: $($remoteResults['Firewall Rule Enabled'])"
             Write-Host "Certificate Present:  $($remoteResults['Certificate Present'])"
        }
         if ($connectionError) {
             Write-Host "Connection Error: $($connectionError.Exception.Message)"
         }
        Write-Host "------------------------------------"


        # FR2.7: Cleanup Session
        if ($session) {
            Write-Verbose "Closing remote session..."
            Remove-PSSession -Session $session
        }
         Write-Host "--- Remote Validation Finished ---"
    }
    'RunCommand' {
         Write-Host "--- Starting Remote Command Execution on $RemoteIP ---"

        # FR3.2: Get Credentials if needed
        if (-not $Credential) {
            Write-Verbose "Credential parameter not provided, prompting user."
            $Credential = Get-Credential -Message "Enter credentials for remote machine '$RemoteIP'"
            if (-not $Credential) {
                Write-Error "Credentials are required for remote command execution. Exiting."
                exit 1
            }
        }

        # FR3.3 / FR2.4: Session Options
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck

        # FR3.3: Attempt Connection
        $session = $null
        $connectionError = $null
        Write-Host "Attempting to connect to $RemoteIP on port $ListenerPort using SSL..."
        try {
            $session = New-PSSession -ComputerName $RemoteIP `
                -Port $ListenerPort `
                -Credential $Credential `
                -UseSSL `
                -SessionOption $sessionOption `
                -ErrorAction Stop
            Write-Host "[Connection Status] Connected successfully." -ForegroundColor Green
        }
        catch {
            $connectionError = $_
            Write-Host "[Connection Status] Failed to connect." -ForegroundColor Red
            Write-Error "Connection Error: $($connectionError.Exception.Message)"
        }


        # FR3.4: Execute Command if connected
        if ($session) {
            Write-Host "Executing command on ${RemoteIP}:"
            Write-Host "'$CommandToRun'"
            Write-Host "--- Remote Output Start ---"
            try {
                 # FR3.5: Stream output
                 # Invoke-Command streams automatically when not assigning to variable
                 Invoke-Command -Session $session -ScriptBlock ([scriptblock]::Create($CommandToRun)) -ErrorAction Stop
                 Write-Host "`n--- Remote Output End ---"
                 Write-Host "[Execution Status] Command executed successfully." -ForegroundColor Green
            } catch {
                 Write-Host "`n--- Remote Output End ---"
                 Write-Error "Failed to execute remote command: $($_.Exception.Message)"
                 Write-Host "[Execution Status] Command execution failed." -ForegroundColor Red
            }
        } else {
             Write-Host "[Execution Status] Skipped due to connection failure." -ForegroundColor Yellow
        }

         # FR3.7: Cleanup Session
        if ($session) {
            Write-Verbose "Closing remote session..."
            Remove-PSSession -Session $session
        }
        Write-Host "--- Remote Command Execution Finished ---"
    }
    'Undo' {
        Write-Host "--- Starting Local PSRP HTTPS Undo ---"

         if (-not (Test-IsAdmin)) {
            Write-Error "Administrative privileges are required for undo operations. Please re-run as Administrator."
            exit 1
        }

        # FR4.1: Remove Listener
        Remove-HttpsListener

        # FR4.2: Remove Firewall Rule
        Remove-FirewallRule -RuleName $DefaultFirewallRuleName

        # FR4.4 & FR4.5 explicitly not done
        Write-Verbose "Note: PowerShell Remoting itself is not disabled, and certificates are not removed by the Undo operation."

        Write-Host "--- Local PSRP HTTPS Undo Finished ---"
    }
    default {
        Write-Error "Invalid parameter set or combination: '$effectiveParameterSetName'. Use -Help for usage."
        exit 1
    }
}

#endregion 