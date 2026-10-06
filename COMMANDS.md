cd ~/Desktop && cat > COMMANDS.md << 'CMD_END'
# WebPT — Commands Runbook

Every command used to build, test, deploy, and run WebPT. Reproduce from a clean Ubuntu/Pop_OS machine.

## 1. Environment setup

    cd ~/Desktop
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt

If `requirements.txt` is missing, create it:

    cat > requirements.txt << 'EOF'
    aiohttp>=3.9.0
    beautifulsoup4>=4.12.0
    dnspython>=2.4.0
    httpx[http2]>=0.27.0
    websockets>=12.0
    pyotp>=2.9.0
    EOF
    pip install -r requirements.txt

## 2. Verify install

    python -m py_compile webpt_v2.py webpt_v4.py webpt_v5.py banner.py
    python webpt_v2_test.py
    python webpt_v4_test.py
    python webpt_v5_test.py

Expected: 10/10, 7/7, 7/7.

## 3. Run against a target (basic)

    python webpt_v5.py https://target.example -c 8

Text report:  `webpt_v5_report.txt`
JSON report:  `webpt_v5_report.json`
Exit code 0 = clean, 1 = high findings, 2 = unreachable.

## 4. Run with family statistics and HTML

    python webpt_v5.py https://target.example -c 8 --families --html report.html

## 5. Run with both HTTP/1.1 and HTTP/2 probes

    python webpt_v5.py https://target.example -c 8 --proto both

## 6. Run with WebSocket upgrade probes

    python webpt_v5.py https://target.example -c 8 --ws --ws-path /socket

## 7. Run authenticated

### 7a. Form login with CSRF extraction

    python webpt_v5.py https://target.example -c 8 \
      --auth-login 'https://target.example/login' \
      --auth-user 'alice' --auth-pass 'hunter2' \
      --auth-csrf-meta 'csrf-token'

### 7b. With post-login verification URL

    python webpt_v5.py https://target.example -c 8 \
      --auth-login 'https://target.example/login' \
      --auth-user 'alice' --auth-pass 'hunter2' \
      --auth-csrf-meta 'csrf-token' \
      --auth-verify 'https://target.example/dashboard' \
      --auth-verify-excludes 'Sign in'

### 7c. HTTP Basic

    python webpt_v5.py https://target.example -c 8 --auth-basic 'alice:hunter2'

### 7d. Bearer token

    python webpt_v5.py https://target.example -c 8 --auth-bearer 'eyJ...'

### 7e. Cookie injection (for OAuth2/SAML targets)

    python webpt_v5.py https://target.example -c 8 --auth-cookie 'session=PASTE_COOKIE'

### 7f. TOTP second factor

    python webpt_v5.py https://target.example -c 8 \
      --auth-login 'https://target.example/login' \
      --auth-user 'alice' --auth-pass 'hunter2' \
      --auth-totp 'JBSWY3DPEHPK3PXP'

Rule: any argument containing `&`, `?`, `=`, `%`, `;`, or whitespace must be single-quoted. Unquoted URLs are truncated by the shell at the first `&`.

## 8. Refresh CDN edge ranges

    python webpt_v5.py --refresh-edges

Fetches Cloudflare, Fastly, and CloudFront ranges. Cache: `~/.cache/webpt/edge_ranges.json`, 24-hour TTL.

## 9. Diff two runs

    python webpt_v5.py --diff old_report.json new_report.json

Prints added, resolved, and retained findings.

## 10. Query the JSON report

    sudo apt install -y jq

Summary only:

    jq '{target, summary}' webpt_v5_report.json

List findings:

    jq '.findings[] | {id, title, severity, boundary: .boundary_crossed, confidence}' webpt_v5_report.json

One finding in full:

    jq '.findings[] | select(.id == "DIFF-054")' webpt_v5_report.json

Every probe one line:

    jq -r '.diffs[] | "\(.status_delta[0])->\(.status_delta[1])  \(.boundary)  \(.relationship[0:80])"' webpt_v5_report.json

Origin candidates:

    jq -r '.origin_candidates[] | "\(.ip_or_host)  class=\(.classification)  conf=\(.confidence)"' webpt_v5_report.json

Compact findings summary:

    jq '{target, started, finished, findings: [.findings[] | {id, title, severity, boundary: .boundary_crossed, confidence, remediation, baseline_curl, variant_curl}]}' webpt_v5_report.json > findings_summary.json

## 11. Targets used in testing

    python webpt_v5.py https://www.cloudflare.com -c 8 --families
    python webpt_v5.py https://www.fu-berlin.de -c 8 --families
    python webpt_v5.py https://easydb.fu-berlin.de -c 8 --families
    python webpt_v5.py https://demo.owasp-juice.shop -c 8 --families --proto both

Note: `juice-shop.herokuapp.com` is dead (Heroku free tier discontinued 2022). Use `demo.owasp-juice.shop` instead.

## 12. Banner check

    python banner.py

Prints the OSAID PT banner. Animates when stdout is a TTY, prints statically when piped.

## 13. Git setup (one time)

    git config --global user.name 'Your Name'
    git config --global user.email 'your@email'

SSH key:

    ssh-keygen -t ed25519 -C "your@github" -f ~/.ssh/id_ed25519_webpt -N ""
    cat ~/.ssh/id_ed25519_webpt.pub

Paste the output at https://github.com/settings/ssh/new.

`~/.ssh/config`:

    cat >> ~/.ssh/config << 'EOF'

    Host github.com
        HostName github.com
        User git
        IdentityFile ~/.ssh/id_ed25519_webpt
        IdentitiesOnly yes
    EOF
    chmod 600 ~/.ssh/config

Test:

    ssh -T git@github.com

Expected: `Hi <username>! You've successfully authenticated...`

## 14. Git push workflow

    cd ~/Desktop
    git add <files>
    git status
    git commit -m "<message>"
    git push

Do not run `git add .` — the Desktop contains unrelated tooling (aircrack-ng, sqlmap, wifite2) that must not enter this repository.

## 15. Patch workflow

One-shot patch with anchor check:

    python3 - << 'PATCH'
    from pathlib import Path
    p = Path("webpt_v2.py")
    s = p.read_text()
    old = '''ANCHOR TEXT'''
    new = '''REPLACEMENT TEXT'''
    assert s.count(old) == 1, f"anchor count={s.count(old)}"
    p.write_text(s.replace(old, new))
    print("patched")
    PATCH

    python -m py_compile webpt_v2.py && echo OK
    python webpt_v2_test.py

Rules:
- Quote the heredoc delimiter (`'PATCH'`) to stop shell expansion.
- Never apply a patch without `assert s.count(old) == 1`.
- Compile and run the harness after every patch.

## 16. Full reset from remote

    cd ~/Desktop
    git fetch origin
    git reset --hard origin/main

## 17. Reading the report

Section 1 — layer, status, architecture (front_end yes/no).
Section 2 — assumptions the engine inferred.
Section 3 — origin candidates with classification.
Section 4 — every probe, signals fired, benign hypothesis each signal rules out.
Section 5 — validated findings. Actionable. Each carries curl repro commands.
Section 6 — signals fired, benign explanation named.
Section 7 — probes with no signal.
Section 8 — one-line summary.

Read Section 3 first. If `candidate-origin` or `leak-suspected`, stop and verify manually.
Read Section 5 second. Reproduce each finding with its curl commands.
Section 6 is the tool explaining what it saw and why it did not fire.

## 18. Interpreting exit codes

0 = clean run, no high or critical findings.
1 = one or more high or critical findings.
2 = target unreachable.

## 19. Common issues

`Repository not found` on push → the remote URL is wrong or the repo does not exist. Verify `git remote -v`.

`Permission denied (publickey)` → SSH key is not registered on GitHub, or `~/.ssh/config` is not pointing at it.

`Invalid username or token` on HTTPS push → paste a personal access token, not the account password. Tokens: https://github.com/settings/personal-access-tokens

`Write access to repository not granted` → fine-grained token lacks `Contents: Read and write` on the target repo.

Shell drops part of the command → an unquoted `&` in a URL backgrounds the rest. Single-quote any argument containing special characters.
