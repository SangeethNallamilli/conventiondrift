# INTERFACES (in-repo extract)

**Owner:** the team (Architect / Technical Lead). **Source:** team `INTERFACES.md` **v1.0, 2026-11-12**.
**Status:** in-repo extract of I-9 only; the source document is still the authority.

This file carries **only the I-9 JSON report** section of the team's `INTERFACES.md`, because I-9 is
the contract this repository's code is reviewed against. The rest of that document (I-1 to I-8,
I-10 to I-14) is a team doc that is not yet in this repository, as `TEST-STRATEGY.md` records. When
the full `INTERFACES.md` lands here, this section moves into it unchanged and this extract is
deleted; until then, this file is the reviewable home of I-9 and it does not restate any other
interface.

This extract does **not** close the traceability gap: `tools/check_test_traceability.py` still needs
`--spec/--traceability/--docs` inputs and those team documents are still outside this repository, so
the tool keeps having no target docs until the full set lands here.

## I-9 JSON report

The report is one JSON object written with sorted keys, 2-space indentation, LF line endings and one
final newline, with no wall-clock timestamp and no absolute path, so the same input gives the same
bytes. `render/jsonreport.py` implements it.

### I-9.1 Report strings are raw data

Every string in the report — rule text, file paths, option names, `new_text`, notes, and
internal-error components and messages — is **raw data**, exactly as it appeared in the repository
or as the fixed internal text defines it. The report promises **no escaping for any sink**: it does
not HTML-escape, shell-quote, Markdown-escape or terminal-escape a value. A consumer that renders a
value into HTML, a shell command, a terminal, Markdown or a log line must escape it for that sink
itself. The one guarantee is JSON validity: each value is a JSON string, so `json.loads` returns the
original text.

### I-9.2 Lone surrogates are emitted, not rejected

A path or rule text that contains a lone (unpaired) UTF-16 surrogate is written as a `\uXXXX` escape
rather than rejected or replaced, so the emitted document is valid JSON but **not strict I-JSON**
(RFC 7493 §2.1 forbids unpaired surrogates). A consumer that requires I-JSON must reject or sanitise
such values itself. This is deliberate: the report is a lossless record of what the repository
contained, discovery already refuses paths it cannot decode, and this is a narrow documented edge
rather than a general promise.
