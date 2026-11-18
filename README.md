# bypass-link-runner

Scratch repo to test the browser-automation bypass
(`bypass_browser.py`, from `~/workspace/bypass-link/` on the dev VM)
on a GitHub Actions runner — ontops.link IP-bans the VM, so a runner's
IP is the next thing to try.

## Files

- `bypass_browser.py` — Playwright script: opens the short link, passes
  the Cloudflare challenge, clicks "Get Link", reads the code-source link
  off the code page, claims the code on that (random) third-party site,
  submits it, prints the destination URL only. Never downloads the
  destination file. No CAPTCHA solving: a gate it cannot pass is reported
  UNSUPPORTED, never a false success.
- `relay_proxy.py` — localhost forward proxy. A VM-egress workaround only;
  on a runner it is skipped via `BYPASS_NO_RELAY=1` (Chromium connects
  directly). The script is otherwise unchanged from the VM copy except
  for that env flag.
- `hosts.fixed` — empty here (runner DNS is clean; the script only
  appends to it if it resolves a code-site host).
- `.github/workflows/bypass-test.yml` — workflow_dispatch: installs
  Playwright + Chromium, runs the script with `--verbose` on the input
  URL (default the anonlink sample), uploads `bypass-run.log` as an
  artifact.

## Run it

Actions → "Bypass test (anonlink)" → Run workflow (URL input defaults
to `https://anonlink.io/qQsoW`).
