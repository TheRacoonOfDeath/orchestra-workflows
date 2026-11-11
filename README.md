# Orchestra workflows

Shared GitHub Actions workflows of the Orchestra plugins (`orchestra-*`).

## Security scan

`.github/workflows/security-scan.yml` scans a plugin on every push to `main`, once a week and on
demand:

| Scanner | What it looks at |
|---------|------------------|
| Psalm taint analysis | PHP: follows request data (`$_GET`, `$_POST`, …) through the code into HTML output, SQL, headers, files and shell commands. `stubs/wordpress-taint.php` tells it which WordPress functions are sinks (`$wpdb->query()`, …) and which escape (`esc_html()`, `$wpdb->prepare()`, `absint()`, …). |
| Semgrep CE (`p/php`, `p/javascript`, `p/secrets`) | Known dangerous PHP and JavaScript patterns and committed secrets |
| CodeQL | JavaScript in `assets/` (only with `javascript: true`) |
| `composer audit` | Known vulnerabilities in the dependencies that ship in the plugin zip (`--no-dev`) |

All code findings appear in the repo's **Security → Code scanning** tab. New findings of **high
or critical** severity also open an issue with the label `security-scan` (`bin/report.php`):

- Psalm: `TaintedSql`, `TaintedShell`, `TaintedEval`, … count as critical; `TaintedHtml`,
  `TaintedHeader`, … count as high.
- Semgrep: rules with severity `ERROR`.
- CodeQL: `security-severity` of 7.0 or more.
- composer audit: advisories rated high or critical.

A finding is recognised by a fingerprint (scanner, rule, file and the code on that line, not the
line number), stored in the issue. As long as an issue with its fingerprint exists, **open or
closed**, the finding does not open another issue. More than 10 new findings at once open one
summary issue instead.

The repos are public, so these issues are public too. They contain the rule and the location,
never secret values.

### False positives

- Close the issue with a comment explaining why. The finding stays in the Security tab, where it
  can be dismissed as "false positive".
- If the code is clearly safe but the scanner cannot see it, mark the line, always with a reason:
  - Semgrep: `// nosemgrep: <rule id> -- reason`
  - Psalm: if a WordPress function is missing from `stubs/wordpress-taint.php`, add it there;
    otherwise `/** @psalm-taint-escape html */` on the function that escapes.

### Adding a repo

Add `.github/workflows/security.yml`:

```yaml
name: Security scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 5 * * 1'   # Mondays 05:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  issues: write

jobs:
  scan:
    uses: TheRacoonOfDeath/orchestra-workflows/.github/workflows/security-scan.yml@v1
    with:
      javascript: true   # only if the plugin has JavaScript
```

Inputs: `javascript` (default false), `create-issues` (default true; false only reports),
`path` and `main-file` (for a plugin that is not at the repo root or whose main file is not
`<repo name>.php`), `tools-ref` (keep at the default).

### Changing the scan

Change it here, check that the **Self-test** workflow (which scans the deliberately vulnerable
`tests/fixture-plugin`) still opens exactly one issue per fixture finding, then move the tag:

```sh
git tag -f v1 && git push -f origin v1
```

A change that needs the callers to change gets a new major tag (`v2`) and the default of
`tools-ref` changes with it.

Locally (PHP 8.3 or later):

```sh
composer install
(cd tests/fixture-plugin && composer install)
sed -e "s#__PLUGIN__#$PWD/tests/fixture-plugin#g" -e "s#__MAIN__#fixture-plugin.php#" \
    -e "s#__TOOLS__#$PWD#g" psalm-taint.xml > /tmp/psalm.xml
(cd tests/fixture-plugin && ../../vendor/bin/psalm --config=/tmp/psalm.xml --taint-analysis --no-cache --report=/tmp/psalm.json)
php bin/report.php psalm-sarif /tmp/psalm.json /tmp/psalm.sarif .
php bin/report.php issues --repo TheRacoonOfDeath/orchestra-workflows --sha main --root . --dry-run /tmp/psalm.sarif
```

## Tests

`.github/workflows/ci.yml` runs on every push and pull request of a plugin:

- `composer check` (coding standard, PHPStan, PHPUnit) on PHP 8.3, the oldest supported version,
  and the latest PHP;
- with `e2e: true`, the end-to-end tests (`composer e2e`) on the oldest supported WordPress
  (`min-wordpress`, default 6.5) and the latest. The plugins' `tests/e2e/run.sh` read the version
  from `E2E_WP_VERSION`.

Add `.github/workflows/ci.yml` to a plugin:

```yaml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  tests:
    uses: TheRacoonOfDeath/orchestra-workflows/.github/workflows/ci.yml@v1
    with:
      e2e: true   # only if the plugin has tests/e2e
```

## Releases

`.github/workflows/release.yml` builds and publishes a release when a version tag is pushed. The
zip is built in GitHub Actions from the tag with the plugin's `build-plugin.sh`, after
`composer check`, never on a developer's machine. The zip and `update.json` get a signed build
provenance (artifact attestation), which anyone can check:

```sh
gh attestation verify orchestra-core-1.2.3.zip --repo TheRacoonOfDeath/orchestra-core \
    --signer-workflow TheRacoonOfDeath/orchestra-workflows/.github/workflows/release.yml
```

The tag must match the `Version:` of the main plugin file and be annotated; its message becomes
the release notes:

```sh
git tag -a v1.2.3 -m "Short user-facing notes" && git push origin v1.2.3
```

Add `.github/workflows/release.yml` to a plugin:

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write
  id-token: write
  attestations: write

jobs:
  release:
    uses: TheRacoonOfDeath/orchestra-workflows/.github/workflows/release.yml@v1
```
