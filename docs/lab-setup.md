# Lab setup notes

These are the original lab configuration notes. The custom quarantine script is not included in this repository; the screenshots establish endpoint and FIM visibility, not a reproducible containment implementation.

## 4) Key capabilities demonstrated
- **Endpoint onboarding and connectivity validation** (Windows + Linux endpoints).
- **Threat hunting** through centralized event review and MITRE ATT&CK mapping.
- **Vulnerability detection + Security Configuration Assessment (CIS)** to surface hygiene and compliance gaps.
- **File Integrity Monitoring (FIM)** to detect file creation/deletion in realtime directories.

FIM (syscheck) configuration reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

## 5) Highlight: VirusTotal + Active Response quarantine (end-to-end)
**FIM detects a file → VirusTotal enriches it → Active Response quarantines it automatically.**

### 5.1 Configure FIM (Kali agent)
```bash
sudo mkdir -p /home/vukhanh732/watch /home/vukhanh732/quarantine
sudo chown -R vukhanh732:vukhanh732 /home/vukhanh732/watch /home/vukhanh732/quarantine
```

In `/var/ossec/etc/ossec.conf` on the Kali agent, add to the existing `<syscheck>` block:
```xml
<directories check_all="yes" realtime="yes">/home/vukhanh732/watch</directories>
```

Restart/validate:
```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl restart wazuh-agent
```

### 5.2 Enable VirusTotal integration (Wazuh server)
In `/var/ossec/etc/ossec.conf` on the Wazuh server:
```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

VirusTotal integration docs: https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html  
`integration` block reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html

Restart manager:
```bash
sudo systemctl restart wazuh-manager
```

### 5.3 Safe test trigger (EICAR)
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /home/vukhanh732/watch/eicar.com
```

### 5.4 Active Response quarantine
Wazuh Active Response supports custom scripts to execute endpoint actions in response to alerts.

- Script path (Kali agent): `/var/ossec/active-response/bin/quarantine.sh`
- Trigger: VirusTotal malicious alert rule id (example: `87105`)
- Result: file moved from `watch/` to `quarantine/` with a timestamped filename.

Active Response docs:
- How to configure: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html
- active-response reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html
- Custom scripts: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html

VirusTotal removal PoC (end-to-end workflow): https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html

