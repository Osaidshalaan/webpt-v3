# Contributing

## Adding probes

Probes live in `ExplainedDiffer.run`. Each variant must declare:

- `label` — short unique name
- `boundary` — which layer boundary it tests
- `tests_assumption` — one sentence describing what the probe proves
- and either `headers`, `method`, or `path_suffix`

Probes that do not map to a named assumption are rejected. The engine's
value comes from staying small and purposeful.

## Adding signals

Signal functions take `(base: LayerSnapshot, var: LayerSnapshot,
variant_headers: Optional[Dict])` and return `Optional[Signal]`. Each
signal must declare:

- `kind` — unique string
- `rules_out` — the benign explanation this signal eliminates
- `severity_weight` — positive for boundary-indicating, negative for
  variance-indicating, zero for ambiguous

## Adding hypotheses

Benign hypotheses must specify the evidence that triggers them. A benign
hypothesis with no evidence present scores zero. This is what keeps the
engine from explaining away real findings.

Boundary hypotheses have no base score; they are scored by coverage only.

## Tests

Every code change must keep `webpt_v2_test.py` at 10/10. Add a new test
for any new signal, hypothesis, or probe family.

## Reporting issues with the tool

Open a GitHub issue with the target's response headers (redact if needed)
and the tool's report.json. The interesting failures are cases where the
tool emitted a finding that turned out to be a false positive, or missed
a finding that manual testing confirmed.
