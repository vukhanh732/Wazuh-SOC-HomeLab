# Lab setup notes

These notes describe a Linux Wazuh agent lab configuration. The screenshots establish endpoint and FIM visibility. The repository quarantine handler has local filesystem tests, but the handler and Wazuh Active Response wiring have not been tested together against a live manager and agent.

## 4) Key capabilities demonstrated
- **Endpoint onboarding and connectivity validation** (Windows + Linux endpoints).
- **Threat hunting** through centralized event review and MITRE ATT&CK mapping.
- **Vulnerability detection + Security Configuration Assessment (CIS)** to surface hygiene and compliance gaps.
- **File Integrity Monitoring (FIM)** to detect file creation/deletion in realtime directories.

FIM (syscheck) configuration reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

## 5) VirusTotal and quarantine handler (lab configuration)

The handler is for a Linux agent and only accepts the Wazuh stateless `add` message shape, rule `87105`, and `data.virustotal.source.file`. It checks that the source is a regular file directly inside the configured watch directory. The Python handler defaults to dry-run; the supplied wrapper passes `--execute` and moves the file to a UUID-named file in the quarantine directory. Use a disposable VM and files while validating this behavior.

### 5.1 Prepare restricted directories (Linux agent)
```bash
sudo install -d -o root -g wazuh -m 0750 /home/vukhanh732/watch
sudo install -d -o root -g wazuh -m 0750 /home/vukhanh732/quarantine
```

Adjust ownership to the account that runs the Active Response on your agent, and ensure that untrusted users cannot write to the watch directory. This restriction reduces the chance that a file is swapped while the handler validates it. The watch and quarantine directories must be on the same filesystem. The handler rejects a symlink at either configured directory path; configure ordinary directories and avoid replacing them with symlinks.

In `/var/ossec/etc/ossec.conf` on the agent, add to the existing `<syscheck>` block:
```xml
<directories check_all="yes" realtime="yes">/home/vukhanh732/watch</directories>
```

Restart/validate:
```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl restart wazuh-agent
```

The handler only moves a file after a matching Active Response arrives. The original source path is validated as a direct child of this watch directory; files elsewhere are rejected.

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

### 5.3 Local synthetic dry-run

Before installing or enabling Active Response, run the filesystem test suite from the repository root:

```bash
python3 -m unittest discover -s tests -v
```

The [synthetic message fixture](../examples/quarantine-alert.sample.json) uses a disposable path. This creates a test file at that path and asks the Python handler to validate it in dry-run mode. The fixture is not a real Wazuh event and this does not test manager/agent integration:

```bash
mkdir -p /tmp/wazuh-quarantine-demo/watch /tmp/wazuh-quarantine-demo/quarantine
chmod 700 /tmp/wazuh-quarantine-demo /tmp/wazuh-quarantine-demo/watch /tmp/wazuh-quarantine-demo/quarantine
printf 'synthetic demo only\n' > /tmp/wazuh-quarantine-demo/watch/eicar.com
python3 tools/quarantine.py \
  --watch-dir /tmp/wazuh-quarantine-demo/watch \
  --quarantine-dir /tmp/wazuh-quarantine-demo/quarantine \
  < examples/quarantine-alert.sample.json
```

Expected output has `"status": "dry-run"`; verify the file remains in `watch` and quarantine is empty. To exercise the move locally, repeat with `--execute` and confirm the source disappears and a UUID-named file appears in quarantine. Remove the temporary demo tree when finished.

### 5.4 Install handler files (Linux agent)

Review the configured paths in `tools/quarantine-wrapper.sh` before copying it. The examples below use the repository checkout at `/home/vukhanh732/Wazuh-SOC-HomeLab`; change that path if needed. Install both the handler and wrapper at the exact locations used by the wrapper:

```bash
sudo install -o root -g wazuh -m 0640 tools/quarantine.py /var/ossec/active-response/bin/quarantine.py
sudo install -o root -g wazuh -m 0750 tools/quarantine-wrapper.sh /var/ossec/active-response/bin/quarantine.sh
```

The wrapper invokes `/usr/bin/python3` and supplies the watch and quarantine paths. Confirm that Python 3 is installed at that path and that the agent's Active Response account can read the script and move files between the two directories. Keep the wrapper executable and the Python file non-executable. First verify the dry-run directly as above; the installed wrapper enables execution.

### 5.5 Configure manager-side Active Response

In the Wazuh manager `/var/ossec/etc/ossec.conf`, define the custom command and a local response for the intended rule. Merge these entries into the existing `<ossec_config>` document:

```xml
<command>
  <name>quarantine-file</name>
  <executable>quarantine.sh</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>quarantine-file</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>
```

This is a non-reversible response: once the file is moved, no timeout action restores it. Validate the rule and configuration for your installed Wazuh version and restart the manager to apply configuration. Enable this only in a disposable lab after confirming the watched path, account permissions, response rule, and recovery procedure. Wazuh's current references: [Active Response configuration](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html), [custom scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html), and [`active-response` options](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html).

### 5.6 Optional EICAR test file
```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | sudo tee /home/vukhanh732/watch/eicar.com >/dev/null
```

Creating an EICAR test file can trigger actual endpoint handling once integration is enabled. Use it only in a disposable VM with the lab directories and rule configured as intended. This repository does not claim a successful live end-to-end response test. Wazuh's VirusTotal removal PoC is documented [here](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-remove-malware-virustotal.html).

