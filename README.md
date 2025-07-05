# Windows Incident Surface - Incident Response Practice
  This repository provides a detailed guide and methodology for analyzing the attack surface and conducting live incident response on Windows systems.  
  It simulates a real-world scenario where you perform safe data collection, identify indicators of compromise, and assess malicious activity using trusted tools.  

  The focus is on:
    - Live response without damaging evidence
    - Hybrid threat hunting and forensic analysis
    - Mapping findings to MITRE ATT&CK techniques

# Objectives
  By completing this incident response practice, you will strengthen your skills in:
    - Performing safe live response on a potentially compromised Windows host
    - Identifying malicious changes in environment variables and PowerShell profiles
    - Detecting unauthorized user accounts and active sessions
    - Investigating suspicious network connections and services
    - Verifying firewall status and identifying unauthorized shares
    - Mapping indicators of compromise to MITRE ATT&CK techniques
    - Documenting findings for reporting and future analysis

# Steps
 1.Use Trusted Tools
  Avoid using potentially compromised built-in tools. Instead, use trusted shells:
    '''C:\Users\Administrator\Desktop\tools\shells\CMD-DFIR.exe'''
    '''C:\Users\Administrator\Desktop\tools\shells\PS-DFIR.exe'''
  
  2.Check Environment Variables
   Export and review environment variables:
cmd: 
  '''set > env_vars.txt'''
  '''type env_vars.txt'''
    Check variables like ComSpec, Path, PSModulePath, TEMP, and TMP.

  3.Review PowerShell Profile
    Look for malicious persistence in PowerShell profiles:
      Common locations:
        '''$HOME\Documents\WindowsPowerShell\profile.ps1'''
        '''$PSHOME\Microsoft.PowerShell_profile.ps1'''
    Check for commands that:
      Clear logs (wevtutil cl)
      Stop event logs (Stop-Service "eventlog")
      Enable credential caching in registry

  4.Replace Malicious Profiles
    If a malicious profile is found:
      cmd:
        '''ren profile.ps1 profile.bak'''
        '''copy PS-DFIR-Profile.ps1 C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'''
  
  5.Enumerate Users and Sessions
    powershell:
        '''Get-LocalUser'''
        '''Get-LocalGroupMember'''
        '''.\PsLoggedon64.exe'''
 Identify suspicious accounts (e.g., additional Admins, enabled Guest).

  6.Check Network Connections
    powershell
        '''Get-NetTCPConnection'''
    Look for unusual ports, services like AnyDesk, or processes in temp folders.

  7.Firewall and Shares
    powershell
        '''Get-NetFirewallProfile'''
        '''Get-CimInstance -Class Win32_Share'''
    Verify no suspicious shares; ensure firewall profiles are active.

# Notes
  Always collect data before taking containment or eradication steps.
  Do not trust built-in tools on a potentially compromised host.
  Document all actions and findings for later analysis or reporting.
