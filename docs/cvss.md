# Source-attributed CVSS

Supply `cvss` on CVE creation:

```json
{"cvss": {"version": "3.1", "score": 7.5,
 "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
 "source": "https://example.org/advisory"}}
```

Versions 3.0, 3.1 and 4.0 are supported. Validation checks score range/precision,
vector syntax and the HTTP(S) source URL; it does not calculate scores or verify
metric choices. Arch severity remains independently reviewed. One selected
assessment is stored, displayed and versioned.
Omit `cvss` or use `null` when no assessment is available.
