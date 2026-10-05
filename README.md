# WebPT v3 — Assumption Engine + Boundary Violation Mapper

A boundary-violation detector for HTTP architectures. Extracts architectural assumptions from a target's observed behaviour, generates a small set of probes that test each assumption, and reports only the probes whose outcome reproduces and cannot be explained by a benign cause.

The engine does not throw payloads. It mutates headers, paths, and methods, and reasons about what the response means.

## Download

Clone the repository:

    git clone https://github.com/Osaidshalaan/webpt-v3.git
    cd webpt-v3

Or download an archive:

- Latest release: https://github.com/Osaidshalaan/webpt-v3/releases/latest
- Source ZIP: https://github.com/Osaidshalaan/webpt-v3/archive/refs/heads/main.zip
- Source tarball: https://github.com/Osaidshalaan/webpt-v3/archive/refs/heads/main.tar.gz

## Quick start

    git clone https://github.com/Osaidshalaan/webpt-v3.git
    cd webpt-v3
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    python webpt_v2.py https://target.example -c 8

Or run the install wrapper:

    ./install.sh

Report files `webpt_v3_report.txt` and `webpt_v3_report.json` are written to the current directory. Read `report.txt` top-down: Section 5 holds validated findings, Section 6 holds diffs that fired but did not reproduce.

## What it does

- Classifies the target's architecture from a single snapshot: front-end present, edge technology, proxy technology, origin technology.
- Enumerates origin candidates from DNS, TLS SAN/CN, and header leaks. Classifies each candidate as `public-endpoint`, `edge-ip`, `candidate-origin`, or `leak-suspected` using multi-signal agreement.
- Extracts architectural assumptions from the observed layers.
- Runs nine differential probes against the target.
- Extracts typed signals from each probe's result.
- Scores a set of named hypotheses against the observed signals.
- Reproduces any interesting diff on a clean connection.
- Emits findings only when the top hypothesis is a boundary violation AND two or more independent positive signals support it AND the delta reproduces on re-probe.

## What it does not do

- Send exploit payloads.
- Brute-force directories, endpoints, or credentials.
- Distinguish a valid finding from a false positive without the validator step. When validation is disabled with `--no-validate`, the report is advisory only.
- Replace manual testing. It narrows the surface. An operator still reads the report.

## Requirements

- Python 3.10+
- No binary dependencies.

    aiohttp>=3.9.0
    beautifulsoup4>=4.12.0
    dnspython>=2.4.0

## Install

    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

## Usage

    python webpt_v2.py https://target.example -c 8 -o report.txt -j report.json

Flags:

- `-c N` — concurrency cap. Default 12. Use 4-8 on shared infrastructure.
- `-o FILE` — text report path. Default `webpt_v3_report.txt`.
- `-j FILE` — JSON report path. Default `webpt_v3_report.json`.
- `--no-validate` — skip the reproduction pass. Faster, noisier.
- `--json-only` — suppress the text report on stdout.

Exit codes:

- `0` — clean run, no high/critical findings.
- `1` — one or more high or critical findings.
- `2` — target unreachable.

## Output

The text report has eight sections.

1. Main Surface Snapshot — layer classification, status, body hash, technology list, architecture summary.
2. Extracted Assumptions — the architectural assumptions the engine inferred from the observed layers.
3. Origin Candidates — every IP or hostname that might be an origin, with confidence, source signals, and classification.
4. Probes Run — every probe with its signals, the benign explanation each signal rules out, and the validation outcome.
5. Findings (validated) — only findings whose delta reproduced on a clean connection. Each carries a curl command that reproduces the exchange.
6. Unconfirmed Diffs — probes that fired signals but did not reach a validated finding. Includes the top hypothesis.
7. Ruled-Out Diffs — probes that produced no signals.
8. Summary — front-end state, assumption count, contradiction count, origin-candidate count, and finding breakdown by severity.

The JSON report is a full dataclass dump of the same data.

## Architecture

    target  -- LayerFingerprinter ---- snapshot, classify layer
            |
            +- OriginCandidateEngine -- enumerate candidates (DNS, TLS, headers)
            |                           fingerprint each (HTTP + TLS)
            |                           classify (edge-ip, candidate-origin, ...)
            |
            +- AssumptionEngine ------ extract assumptions from observation
            |
            +- ExplainedDiffer ------- run probes
            |   +- Signal extraction ------ typed signals with "rules_out"
            |   +- Hypothesis scoring ----- benign vs boundary_violation
            |   +- Validator -------------- re-probe on clean connection
            |
            +- FindingBuilder -------- only validated diffs to findings

## Signal taxonomy

Each signal is an independent observation function. A signal reports what it saw and which benign explanation it rules out.

| Signal | Rules out |
|---|---|
| status_reversal | pure routing variance |
| body_delta | session-driven content variance |
| body_delta_under_cookie | nothing (cookie variance is plausible) |
| sensitive_header_delta | stable upstream identity |
| cache_layer_disagreement | stable edge behaviour |
| compression_variance | application-layer content change |

## Hypothesis scoring

For each probe, the scorer builds a set of named hypotheses. Benign hypotheses carry a base score only if their triggering evidence is present (for example `method semantics differ` requires an `Allow` header and an empty 2xx body). The final score is:

- Benign: base + coverage * 0.1
- Boundary: coverage

`interesting` requires the top hypothesis to be a boundary violation AND at least two positive signals AND at least one corroborating signal (`sensitive_header_delta` or `cache_layer_disagreement`).

## Validation

Any diff marked `interesting` is re-run against the target on a fresh connection with `User-Agent: WebPT-Validator/1.0`. The delta must reproduce exactly: same status, same body hash on both baseline and variant. Diffs that do not reproduce are demoted to Section 6.

## Known limitations

- Only nine probes are run. The set is small by design. Each probe tests a specific assumption about layer contracts, not a fuzzing space.
- Assumption extraction is rule-based. It emits assumptions from a fixed set of default trust models plus architecture-specific signals. It does not infer novel assumptions.
- Edge-IP detection uses a static list of published CDN ranges. New CDNs require a code change.
- TLS SAN harvesting runs only on 443/8443. HTTP-only targets skip the phase.
- The validator treats any body-hash difference as non-reproduction. Some WAF challenge pages embed a per-request nonce; those diffs are intentionally suppressed even when the mutation is real.
- No authentication, no session management, no cookie jar. Probes hit the target as an anonymous client.

## Extending

- Add a probe. Edit the variants list in ExplainedDiffer.run. Each entry must declare the assumption it tests and the boundary it crosses.
- Add a signal. Write a function that takes (base, var, vh) and returns a Signal or None. Add it to SIGNAL_FUNCS.
- Add a hypothesis. Add an entry to the hypotheses list in score_hypotheses. Benign hypotheses must declare their triggering evidence and set base = 0.0 when the evidence is absent.
- Add a CDN range. Append (start_ip, end_ip) to EDGE_RANGES.

## Tests

    python webpt_v2_test.py

Ten tests: main snapshot, architecture classification, assumption extraction, differential probes, curl proof generation, static-fixture zero-false-positive, flaky-upstream rejection, unreachable-target abort, full orchestrator run. Expected: 10/10 passed.

## License

MIT. See LICENSE.
