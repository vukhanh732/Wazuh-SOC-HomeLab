# Wazuh SOC HomeLab

A VMware lab for following endpoint events through detection and investigation. One Wazuh manager monitors Windows, Ubuntu and Kali endpoints, with evidence from agent inventory, MITRE ATT&CK views and file-integrity events.

[Case study](https://security-vu.netlify.app/wazuh.html) · [Lab setup notes](docs/lab-setup.md) · [Offline triage example](examples/triage.sample.md)

## Architecture

```text
Windows ─┐
Ubuntu  ─┼─→ Wazuh manager / indexer / dashboard
Kali    ─┘       → endpoint inventory, FIM, MITRE views
                  → VirusTotal enrichment / lab response configuration

Exported JSONL alerts → Python triage tool → Markdown investigation summary
```

The lab setup notes describe the VirusTotal and Active Response quarantine configuration. The custom quarantine script is not checked in, so automated containment is not a turnkey feature of this repository. The new triage utility runs separately on exported alerts and does not connect to the manager or change files on endpoints.

## Evidence from the lab

![Three monitored endpoints in the Wazuh agent inventory](evidence/agents.png)

| Evidence | What it shows |
| --- | --- |
| [Windows overview](evidence/windows_overview.png) / [details](evidence/windows_details.png) | Endpoint inventory, vulnerability and configuration views |
| [Kali overview](evidence/kali_overview.png) / [MITRE events](evidence/mitre_events.png) | Linux telemetry and rule-to-technique mapping |
| [File integrity events](evidence/fim_events.png) | EICAR test-file creation/deletion events |

These are existing lab captures. They do not measure production coverage, response speed or confirmed malicious incidents.

## Summarize an alert export

Python 3.10+, standard library only. Input is one Wazuh alert JSON object per line, such as an exported `alerts.json` file.

```bash
git clone https://github.com/vukhanh732/Wazuh-SOC-HomeLab.git
cd Wazuh-SOC-HomeLab
python3 tools/triage.py examples/alerts.sample.jsonl --min-level 7
python3 tools/triage.py /path/to/alerts.json --min-level 10 --agent 003 --output triage.md
```

The report groups matching alerts by rule level, endpoint, MITRE technique ID and detection rule. `--agent` accepts an exact agent name or ID. Counts describe **alerts**, not distinct incidents or confirmed attacks. Endpoints with the same display name are grouped together; technique IDs are counted once per alert.

The bundled JSONL and [generated report](examples/triage.sample.md) are **synthetic demonstration fixtures**, separate from the real lab screenshots. No credentials or live manager access are needed to try them.

Malformed JSON, invalid levels and unsupported field shapes stop processing with exit code `2` and a line number. Output is written only after parsing succeeds. Untrusted fields are escaped for Markdown/HTML rendering.

## Verify

```bash
python3 -m unittest discover -s tests -v
```

Regression tests cover filtering/counting, technique deduplication, malformed alerts and untrusted report text.

## Reproduce the lab

See [lab setup notes](docs/lab-setup.md) for FIM and VirusTotal configuration and the EICAR test workflow. Addresses and paths are examples from a private VMware NAT network. Bring your own Wazuh installation and VirusTotal API key. Follow the linked official Wazuh documentation for the installed version.

Next work: include a reviewed response implementation, test failed response actions, and add noisier investigation scenarios. The offline triage tool is tested locally; it has not been deployed as a live SOC integration.
