# Linz 3-Minute Demo Script

## 0:00-0:20 - Hook

Security teams get hundreds of alerts a day. A single alert can take hours to investigate and close. Linz fixes that by turning Splunk alerts into autonomous incident response.

## 0:20-0:45 - Trigger the Attack

```bash
python demo/attack_simulator.py --scenario ssh_bruteforce
```

This simulates 138 failed SSH logins from one external IP in under 4 minutes.

## 0:45-1:30 - Watch the Loop

```bash
python -m agent.orchestrator --once
```

Show the four logs:

```text
[PERCEIVE] New alert: SA-AccessAnomaly-1234
[REASON] SSH brute force | confidence=0.91 | action=block_ip
[EXECUTE] block_ip -> SUCCESS
[PROVE] Report ... written to Splunk
```

## 1:30-2:00 - Show the Proof

Open `.linz_demo/linz_reports.jsonl` or Splunk `index=linz_reports`. Highlight the original alert, AI reasoning, action, and MTTR.

## 2:00-2:30 - Show Generalization

```bash
python demo/attack_simulator.py --scenario port_scan
python -m agent.orchestrator --once
```

Linz creates a ticket instead of blocking, showing it reasons about each alert individually.

## 2:30-2:50 - Architecture

Show `architecture.png`: Splunk MCP Server feeds the agent loop, Claude reasons, playbooks act, and reports are written back to Splunk.

## 2:50-3:00 - Close

Mean time to respond: under 60 seconds. No human intervention required. Linz, because alerts should close themselves.
