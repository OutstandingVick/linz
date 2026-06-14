# Linz 3-Minute Demo Script

## Recording Setup

Open three things before recording:

- Terminal at `/Users/macbook/Documents/Linz`
- The GitHub repo: `https://github.com/OutstandingVick/linz`
- `architecture.png`

Use a large terminal font. Keep the video under 3 minutes.

## 0:00-0:20 - Hook

**Screen:** GitHub repo or README title.

**Voiceover:** Security teams do not lose time because Splunk cannot detect threats. They lose time after detection, when someone still has to triage the alert, decide what to do, take action, and document the incident. Linz closes that loop.

## 0:20-1:10 - Attack One: Block The Source

**Screen:** Terminal.

```bash
python3 demo/run_demo.py --scenario ssh_bruteforce
```

**Voiceover:** I am simulating an SSH brute-force attack: 138 failed login attempts from one external IP. Linz perceives the Splunk alert, reasons over the event context, identifies SSH brute force with 91 percent confidence, executes the block IP playbook, and writes a report back to the Splunk report index.

**On screen, pause on:**

```text
[PERCEIVE] New alert
[REASON] SSH brute force | confidence=0.91 | action=block_ip
[EXECUTE] block_ip -> SUCCESS
[PROVE] Report ... written to Splunk
```

## 1:10-1:45 - Proof: Show The Audit Trail

**Screen:** Terminal.

```bash
python3 demo/show_reports.py --latest
```

**Voiceover:** The important part is not just that Linz acted. It proves what happened. The report includes the original alert, the AI reasoning, MITRE ATT&CK mapping, action taken, and MTTR. That audit trail lives where SecOps teams already work: Splunk.

## 1:45-2:20 - Attack Two: Different Threat, Different Action

**Screen:** Terminal.

```bash
python3 demo/run_demo.py --scenario port_scan
```

**Voiceover:** Linz is not hardcoded to block everything. Here, a port scan receives moderate confidence, so Linz creates an incident ticket instead of blocking immediately. Same loop, different decision.

**On screen, pause on:**

```text
[REASON] port scan | confidence=0.72 | action=create_ticket
[EXECUTE] create_ticket -> SUCCESS
```

## 2:20-2:45 - Architecture

**Screen:** `architecture.png`.

**Voiceover:** The architecture is intentionally simple: Splunk MCP is the data boundary, the Linz agent runs perceive, reason, execute, and prove, Claude is used for structured triage, and playbooks handle response actions like blocking, Slack alerts, Jira tickets, or endpoint isolation.

## 2:45-3:00 - Close

**Screen:** GitHub repo.

**Voiceover:** Linz turns Splunk alerts into closed incidents with an auditable response trail. Mean time to respond drops from hours to seconds. Linz, because alerts should close themselves.

## Backup One-Take Command

If you need a single command for the video:

```bash
python3 demo/run_demo.py --scenario all
```
