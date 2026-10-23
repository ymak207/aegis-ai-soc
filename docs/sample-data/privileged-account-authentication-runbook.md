# Runbook: Repeated authentication failures on a privileged account

**Purpose:** Defensive triage guidance for a synthetic SOC demonstration. This is not a response automation.

## Trigger

An alert reports repeated failed authentication attempts associated with a privileged account, especially when the attempts span multiple source addresses or are followed by a successful login.

## Evidence to collect

1. Confirm the event timestamp and timezone, source IP, destination host, username, authentication protocol, and result.
2. Correlate authentication failures for the same account and source over a 15-minute window.
3. Check whether a successful authentication followed the failures; record the timestamp and originating host.
4. Compare the source IP and host against the organization's approved asset inventory and locally maintained indicator list.
5. Review identity-provider, VPN, endpoint, and privileged-access logs for related activity.
6. Preserve original event IDs and relevant log excerpts. Do not treat a single indicator match as proof of compromise.

## Triage guidance

- **Higher concern:** privileged account, repeated failures followed by success, unfamiliar source, impossible travel, or concurrent endpoint alerts.
- **Moderate concern:** repeated failures from a known managed device with no successful login and a plausible user explanation.
- **Lower concern:** isolated failures consistent with a documented password change or approved test, after corroboration.

Severity should be assigned using the organization's incident policy and corroborating evidence, not this runbook alone.

## Analyst next steps

1. Validate the source, timestamp, account ownership, and affected asset with an independent source.
2. Correlate related events and locally available threat indicators.
3. Contact the identity or system owner through the approved process if activity remains unexplained.
4. If compromise is suspected, follow the approved incident-response playbook and obtain authorized human approval before containment or credential changes.
5. Record evidence, confidence, decisions, and unresolved questions in the case.

## Safety and limitations

This runbook contains no live credentials, real user data, or executable response commands. The AEGIS demonstration uses synthetic events and reserved documentation IP addresses. Recommendations are advisory; this document does not authorize blocking an address, disabling an account, or changing a system.
