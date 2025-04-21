# PSRP Helper Script

**Version: 1.0**

This PowerShell script (`psrp-helper.ps1`) simplifies the configuration and use of PowerShell Remoting Protocol (PSRP) over HTTPS.

It helps administrators:
*   Easily configure the **local machine** to accept secure PSRP connections using a self-signed certificate.
*   Validate the PSRP HTTPS configuration on a **remote machine**.
*   Execute commands securely on a **remote machine** via PSRP HTTPS.
*   Undo the local configuration changes made by the script.

## Features

*   **Local Setup (Default Mode):**
    *   Checks and warns if the network profile isn't 'Private'.
    *   Enables PowerShell Remoting (`Enable-PSRemoting -Force`).
    *   Creates/ensures a Windows Firewall rule named "WINRM-HTTPS" for TCP port 5986.
    *   Identifies a suitable local IP address.
    *   Generates/ensures a self-signed certificate (CN=LocalIP) valid for 1 year.
    *   Creates/configures a WinRM HTTPS listener using the certificate.
    *   Requires **Administrative Privileges**.
*   **Remote Validation Mode (`-Test`):**
    *   Attempts to connect to a remote machine via PSRP HTTPS (port 5986).
    *   Checks remote listener, firewall rule, and certificate presence.
    *   Requires `-RemoteIP` and prompts for `-Credential` if not provided.
    *   Bypasses certificate CN/CA checks for ease of use with self-signed certs.
*   **Remote Command Execution Mode (`-RunCommand`):**
    *   Connects to a remote machine via PSRP HTTPS.
    *   Executes a specified command string (`-CommandToRun`).
    *   Streams command output.
    *   Requires `-RemoteIP`, `-CommandToRun`, and prompts for `-Credential` if not provided.
    *   Bypasses certificate CN/CA checks.
*   **Undo Mode (`-Undo`):**
    *   Removes the WinRM HTTPS listener created by the script.
    *   Removes the "WINRM-HTTPS" firewall rule created by the script.
    *   Does **not** disable PowerShell Remoting or remove certificates.
    *   Requires **Administrative Privileges**.
*   **Help (`-Help`) & Version (`-Version`):** Displays usage information or script version.

## Requirements

*   Windows Operating System
*   PowerShell 5.1 or later
*   Administrative privileges are required for Local Setup and Undo modes.

## Usage

Open PowerShell as an Administrator for setup or undo operations.

**1. Configure Local Machine (Default):**

```powershell
.\psrp-helper.ps1 [-Verbose] [-WhatIf]
```
*   `-Verbose`: Shows detailed step-by-step information.
*   `-WhatIf`: Shows what changes would be made without actually making them.

**2. Validate Remote Machine Configuration:**

```powershell
.\psrp-helper.ps1 -Test -RemoteIP <Remote_IP_or_Hostname> [-Credential <PSCredential>] [-Verbose]
```
*   Replace `<Remote_IP_or_Hostname>` with the target machine's IP or name.
*   If `-Credential` is omitted, you will be prompted securely.
    *   Example using prompt: `.\psrp-helper.ps1 -Test -RemoteIP 192.168.1.50`
    *   Example providing credential: `.\psrp-helper.ps1 -Test -RemoteIP 192.168.1.50 -Credential (Get-Credential)`

**3. Execute Remote Command:**

```powershell
.\psrp-helper.ps1 -RunCommand -RemoteIP <Remote_IP_or_Hostname> -CommandToRun "<Your_Command>" [-Credential <PSCredential>] [-Verbose]
```
*   Replace `<Your_Command>` with the command you want to run remotely (e.g., `"Get-Service WinRM"`, `"hostname"`).
*   Example: `.\psrp-helper.ps1 -RunCommand -RemoteIP server01 -CommandToRun "ipconfig /all"`

**4. Undo Local Configuration:**

```powershell
.\psrp-helper.ps1 -Undo [-Verbose] [-WhatIf]
```

**5. Get Help:**

```powershell
.\psrp-helper.ps1 -Help
# OR
Get-Help .\psrp-helper.ps1 -Full
```

**6. Get Version:**

```powershell
.\psrp-helper.ps1 -Version
```

## Security Considerations

*   **Administrator Privileges:** The script requires elevation for modifying local WinRM settings, firewall rules, and certificates.
*   **Self-Signed Certificates:** The script uses self-signed certificates based on the local machine's IP address. This is convenient for testing or internal networks but doesn't provide the chain of trust of a CA-issued certificate.
*   **Certificate Validation Skipped:** When connecting to remote machines (`-Test`, `-RunCommand`), the script uses `New-PSSessionOption -SkipCACheck -SkipCNCheck`. This bypasses standard certificate validation, trusting the certificate presented by the remote host. This is necessary for easy connection with self-signed certificates but means you should ensure you are connecting to the intended machine, especially in untrusted networks.
*   **Credentials:** Use the `-Credential` parameter or the secure prompt (`Get-Credential`) to handle remote machine credentials. Avoid hardcoding credentials in scripts.

## Contributing

(Optional: Add guidelines if you plan for others to contribute).

## License

(Optional: Specify a license, e.g., MIT License). 

