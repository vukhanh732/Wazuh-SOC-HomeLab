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

The repository includes a constrained Linux Active Response quarantine handler. It accepts only a stateless `add` message for rule `87105` with `data.virustotal.source.file` directly inside a configured watch directory. It defaults to dry-run; the supplied wrapper enables moving files into a separate quarantine directory. Review the [installation and test notes](docs/lab-setup.md) before enabling it. The handler has local filesystem tests, but has not been validated against a live Wazuh manager or agent.

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

Regression tests cover triage parsing and output, plus quarantine path/rule validation, dry-run behavior, symlinks, missing files and file moves. They use temporary directories and synthetic messages; they do not contact a Wazuh manager or perform a live Active Response integration test.

## Reproduce the lab

See [lab setup notes](docs/lab-setup.md) for FIM and VirusTotal configuration and the EICAR test workflow. Addresses and paths are examples from a private VMware NAT network. Bring your own Wazuh installation and VirusTotal API key. Follow the linked official Wazuh documentation for the installed version.

The quarantine message at [examples/quarantine-alert.sample.json](examples/quarantine-alert.sample.json) is synthetic. The offline triage tool and quarantine handler are tested locally; neither has been deployed as a live SOC integration.
