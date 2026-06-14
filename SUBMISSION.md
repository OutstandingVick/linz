# Linz Submission Pack

## Devpost Project Title

Linz

## Short Pitch

Linz is an autonomous security response agent for Splunk that detects, reasons, acts, and reports, turning alerts into closed incidents without waiting for a human analyst.

## Inspiration

Security teams do not lose time because Splunk cannot detect important events. They lose time in the gap after detection: triaging the alert, deciding whether it is real, choosing a response, executing that response, and documenting the outcome. Linz was built to close that loop.

## What It Does

Linz polls Splunk security alerts through a Splunk MCP client, normalizes each alert, uses an AI triage agent to classify the threat and choose a response, executes a playbook, and writes a structured incident report back to Splunk. The report includes the original alert, AI reasoning, confidence, MITRE ATT&CK mapping, action taken, and MTTR.

## How We Built It

- Python async orchestration for the incident loop
- Splunk MCP client abstraction for reads and writes
- Claude Sonnet-ready triage prompt with deterministic demo fallback
- Pluggable response playbooks for block IP, isolate endpoint, create ticket, and Slack alert
- Local demo backend that mirrors Splunk queues and report indexes while live credentials are being configured

## Best Use Of Splunk MCP Server

The Splunk MCP layer is not an add-on. It is the boundary for both sides of the loop: Linz reads security alerts through the MCP client and writes the final incident report back into the Splunk report index. That gives security teams an auditable record inside the same operational system where the alert began.

## Demo Flow

1. Run `python3 demo/run_demo.py --scenario ssh_bruteforce`
2. Linz injects a brute-force SSH alert
3. The agent logs `[PERCEIVE]`, `[REASON]`, `[EXECUTE]`, and `[PROVE]`
4. Linz blocks the source IP in the demo firewall playbook
5. The final report is written to `linz_reports`
6. Run `python3 demo/run_demo.py --scenario port_scan` to show a different decision path: create ticket instead of block

## Judging Criteria Mapping

**Technological Implementation:** Clean Python modules, async orchestration, MCP integration boundary, structured AI output, and pluggable playbooks.

**Design:** Clear phase-labeled terminal output, concise incident report schema, and a root architecture diagram.

**Potential Impact:** Reduces response time from hours to seconds for common SOC alerts while preserving a full audit trail.

**Quality Of The Idea:** Linz is agentic operations, not alert visualization. It perceives, reasons, executes, and proves.

## Required Checklist

- [x] Open-source code repository
- [x] MIT license
- [x] Root-level architecture diagram
- [x] Dependencies listed
- [x] Setup and run instructions
- [x] Demo fixtures
- [ ] Public demo video under 3 minutes
- [ ] Devpost form submitted
