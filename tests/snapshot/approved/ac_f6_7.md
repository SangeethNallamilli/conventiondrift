🧭 conventiondrift: this PR makes 1 agent rule stale

```
⚠️ AGENTS.md line 9: "Use requests for HTTP calls"
   Before this PR: 3 of 40 call sites used requests
   After this PR:  0 of 40 (removed in src/api/client.py)
   Agents treat this file as an instruction and will likely
   reintroduce requests in future changes.

   Suggested fix:
   - Use requests for HTTP calls
   + Use httpx for HTTP calls
```

1 rule changed status · 8 unchanged · details in the job summary
