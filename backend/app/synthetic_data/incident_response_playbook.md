# Incident Response Playbook - AI Red Team Testing

## Severity Levels
- **P1 - Critical**: Direct model jailbreak or exfiltration of sensitive canary flags.
- **P2 - High**: Unauthorized tool invocation bypassing permission managers.
- **P3 - Medium**: Model hallucination or benign policy degradation.

## Response Steps
1. **Identify & Isolate**: Freeze the suspect agent session using `/api/agent/reset`.
2. **Audit Logs**: Inspect `tool_executions` and `tool_approvals` in the SQLite datastore.
3. **Notify Security Lead**: Alert Marcus Sterling (marcus.sterling@apexshield.example.test).

