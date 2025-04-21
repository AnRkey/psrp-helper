# Product Requirements Document: PSRP Helper Script

**Version:** 1.0
**Date:** $(Get-Date -Format 'yyyy-MM-dd')

## 1. Introduction

This document outlines the requirements for the PSRP Helper Script, a PowerShell tool designed to simplify the configuration and validation of PowerShell Remoting Protocol (PSRP) connections over HTTPS. The script aims to provide administrators with a streamlined way to set up the local machine for secure remote management and to test or interact with remote machines using PSRP.

## 2. Goals

*   **Simplify Local Setup:** Automate the steps required to configure the local machine for secure PSRP over HTTPS using a self-signed certificate.
*   **Validate Remote Configuration:** Provide a mechanism to test if a remote machine is correctly configured for PSRP over HTTPS.
*   **Enable Remote Execution:** Allow users to securely run commands on a remote machine via PSRP over HTTPS.
*   **Provide Reversibility:** Offer an option to undo the local configuration changes made by the script.
*   **Improve Usability:** Offer clear usage instructions, feedback, and error handling.

## 3. Features / User Stories

*   **As an administrator, I want to run the script without parameters to automatically configure my local machine for PSRP over HTTPS, so I can quickly enable secure remote management.**
    *   Sets network profile to Private.
    *   Enables PowerShell Remoting.
    *   Creates/ensures a firewall rule for PSRP HTTPS (TCP 5986).
    *   Generates/ensures a self-signed certificate based on the local IP address.
    *   Creates/configures a PSRP HTTPS listener using the certificate.
*   **As an administrator, I want to validate the PSRP HTTPS configuration on a remote machine, so I can troubleshoot connection issues.**
    *   Takes remote IP/hostname and credentials as input.
    *   Attempts to establish a PSRP session over HTTPS (port 5986).
    *   Checks for listener configuration, firewall rule presence/status, and certificate presence on the remote machine.
    *   Provides a summary report of the validation checks.
*   **As an administrator, I want to execute a specific command on a remote machine using PSRP over HTTPS, so I can perform remote administrative tasks securely.**
    *   Takes remote IP/hostname, command string, and credentials as input.
    *   Establishes a PSRP session over HTTPS.
    *   Executes the provided command on the remote machine.
    *   Streams the command output.
*   **As an administrator, I want to undo the local PSRP HTTPS configuration performed by the script, so I can revert the changes if necessary.**
    *   Removes the PSRP HTTPS listener created by the script.
    *   Removes the firewall rule (default name: "WINRM-HTTPS") created by the script.
    *   Does *not* disable PowerShell Remoting or remove certificates.
*   **As a user, I want to view help information for the script, so I can understand its usage and parameters.**
*   **As a user, I want to view the script's version number, so I can track updates or report issues accurately.**

## 4. Functional Requirements

### 4.1. Local Setup Mode (Default)

*   **FR1.1:** The script MUST check if the network connection profile is 'Private'. If not, it SHOULD attempt to set it to 'Private'. Failure SHOULD be logged but not halt execution.
*   **FR1.2:** The script MUST enable PowerShell Remoting (`Enable-PSRemoting -Force`). Failure MUST be logged and potentially halt execution or affect overall success status.
*   **FR1.3:** The script MUST ensure a Windows Firewall rule exists and is enabled for inbound TCP traffic on port 5986 (default name: "WINRM-HTTPS"). If the rule does not exist, it MUST create it. Failure MUST be logged.
*   **FR1.4:** The script MUST determine a suitable local non-loopback, non-APIPA IPv4 address. Failure to find an IP MUST halt execution.
*   **FR1.5:** The script MUST ensure a valid self-signed X.509 certificate exists in the local machine's 'My' certificate store with the `CN=` set to the determined IP address.
    *   **FR1.5.1:** If a valid certificate exists and is not expiring soon (e.g., within 30 days), it MUST be used.
    *   **FR1.5.2:** If a certificate exists but is expiring soon, the script SHOULD prompt (respecting `-WhatIf`) to remove the old one and create a new one.
    *   **FR1.5.3:** If no certificate exists, or renewal was approved, the script MUST create a new self-signed certificate valid for 1 year. Failure MUST halt execution.
*   **FR1.6:** The script MUST ensure a PSRP listener exists for HTTPS transport (`*` address) using the certificate identified/created in FR1.5.
    *   **FR1.6.1:** If no HTTPS listener exists, it MUST be created.
    *   **FR1.6.2:** If an HTTPS listener exists but uses a different certificate thumbprint, it MUST be updated to use the correct thumbprint.
    *   **FR1.6.3:** Failures in listener creation/update MUST be logged.
*   **FR1.7:** The script MUST provide status updates for each major step (`Write-SetupStepStatus`).
*   **FR1.8:** The script MUST report overall success or failure/warnings upon completion.
*   **FR1.9:** Requires administrative privileges.

### 4.2. Remote Validation Mode (`-t`, `-Test`)

*   **FR2.1:** Requires `-RemoteIP` parameter (IP or hostname).
*   **FR2.2:** Requires credentials. If `-Credential` parameter is omitted, MUST prompt the user securely (`Get-Credential`). Script MUST exit if credentials are not provided.
*   **FR2.3:** MUST attempt to establish a PSRP session to the `RemoteIP` on TCP port 5986 using SSL/TLS (`New-PSSession -UseSSL`).
*   **FR2.4:** MUST bypass certificate authority (CA) and common name (CN) checks for the session (`New-PSSessionOption -SkipCACheck -SkipCNCheck`).
*   **FR2.5:** If the session is established, MUST execute remote commands (`Invoke-Command`) to check:
    *   Existence of a PSRP HTTPS listener configuration.
    *   Existence and enabled state of the "WINRM-HTTPS" firewall rule.
    *   Presence of *any* certificate in the remote machine's 'My' store.
*   **FR2.6:** MUST display a summary report showing:
    *   Connection attempt status (Connected/Failed).
    *   Session establishment status (True/False).
    *   Remote check results (Listener Configured, Firewall Rule Present, Firewall Rule Enabled, Certificate Present) if the session was established and remote commands succeeded.
    *   Error messages if connection or remote command execution failed.
*   **FR2.7:** MUST properly close the PSRP session (`Remove-PSSession`).

### 4.3. Remote Command Execution Mode (`-c`, `-RunCommand`)

*   **FR3.1:** Requires `-RemoteIP` and `-CommandToRun` parameters.
*   **FR3.2:** Requires credentials. If `-Credential` parameter is omitted, MUST prompt the user securely (`Get-Credential`). Script MUST exit if credentials are not provided.
*   **FR3.3:** MUST attempt to establish a PSRP session similar to Validation Mode (FR2.3, FR2.4).
*   **FR3.4:** If the session is established, MUST execute the command string provided in `-CommandToRun` on the remote machine (`Invoke-Command`).
*   **FR3.5:** MUST stream the output (stdout/stderr) of the remote command to the local console.
*   **FR3.6:** MUST report success or failure of connection/execution.
*   **FR3.7:** MUST properly close the PSRP session (`Remove-PSSession`).

### 4.4. Undo Mode (`-u`, `-Undo`)

*   **FR4.1:** MUST attempt to remove the PSRP HTTPS listener configured by this script (`WSMan:\localhost\Listener\*\Transport=HTTPS`).
*   **FR4.2:** MUST attempt to remove the firewall rule named "WINRM-HTTPS".
*   **FR4.3:** MUST report the success or failure of each removal step.
*   **FR4.4:** MUST NOT disable PowerShell Remoting.
*   **FR4.5:** MUST NOT remove any certificates.
*   **FR4.6:** Requires administrative privileges.

### 4.5. Help Mode (`-h`, `-Help`)

*   **FR5.1:** MUST display a custom help message outlining the script's purpose, usage examples, and parameters.
*   **FR5.2:** MUST exit immediately after displaying help.

### 4.6. Version Mode (`-v`, `-Version`)

*   **FR6.1:** MUST display the script's version number.
*   **FR6.2:** MUST exit immediately after displaying the version.

### 4.7. General

*   **FR7.1:** The script MUST support `-Verbose` for detailed operational logging.
*   **FR7.2:** The script MUST support `-WhatIf` for operations that make system changes (firewall rule creation/removal, certificate creation/removal, listener creation/update/removal).

## 5. Non-Functional Requirements

*   **NFR1 (Security):** Credentials for remote connections must be handled securely (using `PSCredential` object, prompting user when necessary). Remote connections must use HTTPS. Certificate checks are bypassed by default for validation/command modes for ease of use with self-signed certs, but this implies a trust-on-first-use model or manual verification.
*   **NFR2 (Usability):** Output should be clear and informative, indicating the status of operations. Error messages should be user-friendly. Help and version information must be easily accessible.
*   **NFR3 (Reliability):** The script should handle common errors gracefully (e.g., listener not found, rule already exists, failed connection). It should clean up resources like PSRP sessions.
*   **NFR4 (Maintainability):** The code should be well-structured with functions for distinct operations and include comments where necessary.

## 6. Out of Scope

*   Configuring PSRP over HTTP.
*   Configuring PSRP over SSH.
*   Managing certificate trust or CAs.
*   Advanced PSRP session configuration options beyond basic HTTPS setup.
*   Removing the generated self-signed certificate (must be done manually or via other tools).
*   Disabling PowerShell Remoting (only enabling is performed). 