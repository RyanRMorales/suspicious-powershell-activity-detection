# Suspicious PowerShell Activity Detection

## Overview

This project demonstrates the detection and investigation of suspicious PowerShell activity within an Active Directory and Splunk homelab.

Using PowerShell on a monitored Windows workstation (WS01), I generated controlled encoded command activity using the `-EncodedCommand` parameter. Sysmon process creation telemetry was forwarded to Splunk, where I investigated Event ID 1 and analyzed fields including the process image, parent process, command line, and user context.

An SPL detection was developed to identify PowerShell executions containing encoded command parameters such as `-EncodedCommand` and `-enc`. The completed detection was configured as a scheduled high-severity Splunk alert and validated using fresh controlled PowerShell activity.

## Lab Environment

| System | IP Address | Role |
|---|---|---|
| DC01 | 192.168.100.10 | Domain Controller / Splunk Enterprise |
| WS01 | 192.168.100.20 | Domain-joined Windows workstation / monitored endpoint |

The environment operates on an isolated virtual network. WS01 is configured with Sysmon and the Splunk Universal Forwarder, allowing process creation telemetry to be collected and forwarded to Splunk Enterprise on DC01 for investigation and detection.
