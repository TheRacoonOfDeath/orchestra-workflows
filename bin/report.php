<?php

/*
 * The reporting part of the security scan.
 *
 *   report.php psalm-sarif <psalm.json> <out.sarif> <repository root>
 *       Turns Psalm's JSON report into SARIF, keeping only the taint findings.
 *
 *   report.php issues --repo OWNER/NAME --sha SHA --root DIR [--audit audit.json]
 *                     [--max 10] [--dry-run] <file.sarif>...
 *       Opens a GitHub issue for every new high or critical finding. Findings are recognised by a
 *       fingerprint in the issue body; an issue with the label, open or closed, silences its
 *       finding. Needs `gh` with GH_TOKEN, except with --dry-run.
 */

declare(strict_types=1);

const LABEL = 'security-scan';
const HIGH = 7.0;
const CRITICAL = 9.0;

/**
 * Psalm's taint issues by how severe they are; others count as medium.
 */
const PSALM_SEVERITY = [
    'TaintedSql' => 9.0,
    'TaintedShell' => 9.8,
    'TaintedEval' => 9.8,
    'TaintedInclude' => 9.8,
    'TaintedCallable' => 9.0,
    'TaintedUnserialize' => 9.0,
    'TaintedFile' => 8.0,
    'TaintedSSRF' => 8.0,
    'TaintedHtml' => 7.5,
    'TaintedTextWithQuotes' => 7.5,
    'TaintedHeader' => 7.0,
    'TaintedCookie' => 7.0,
    'TaintedLdap' => 7.0,
    'TaintedXpath' => 7.0,
    'TaintedSleep' => 5.0,
    'TaintedSystemSecret' => 5.0,
    'TaintedUserSecret' => 5.0,
];

/**
 * @param list<string> $argv
 */
function main(array $argv): int
{
    $command = $argv[1] ?? '';
    $arguments = array_slice($argv, 2);

    return match ($command) {
        'psalm-sarif' => psalmSarif(...$arguments),
        'issues' => issues($arguments),
        default => usage(),
    };
}

function usage(): int
{
    fwrite(STDERR, "Usage: report.php psalm-sarif <psalm.json> <out.sarif> <root>\n"
        . "       report.php issues --repo OWNER/NAME --sha SHA --root DIR [--audit FILE] [--max N] [--dry-run] <file.sarif>...\n");

    return 2;
}

function psalmSarif(string $input = '', string $output = '', string $root = ''): int
{
    if ($input === '' || $output === '' || $root === '') {
        return usage();
    }

    $root = rtrim((string) realpath($root), '/') . '/';
    $rules = [];
    $results = [];
    foreach (readJson($input) as $issue) {
        if (!is_array($issue) || !is_string($issue['type'] ?? null) || !str_starts_with($issue['type'], 'Tainted')) {
            continue;
        }
        $type = $issue['type'];
        $severity = PSALM_SEVERITY[$type] ?? 5.0;
        $rules[$type] = [
            'id' => $type,
            'name' => $type,
            'shortDescription' => ['text' => $type],
            'helpUri' => 'https://psalm.dev/docs/running_psalm/issues/' . $type . '/',
            'properties' => ['security-severity' => number_format($severity, 1), 'tags' => ['security']],
        ];
        $path = (string) ($issue['file_path'] ?? '');
        $results[] = [
            'ruleId' => $type,
            'level' => $severity >= HIGH ? 'error' : 'warning',
            'message' => ['text' => (string) ($issue['message'] ?? $type)],
            'locations' => [[
                'physicalLocation' => [
                    'artifactLocation' => ['uri' => str_starts_with($path, $root) ? substr($path, strlen($root)) : $path],
                    'region' => [
                        'startLine' => (int) ($issue['line_from'] ?? 1),
                        'endLine' => (int) ($issue['line_to'] ?? $issue['line_from'] ?? 1),
                        'startColumn' => (int) ($issue['column_from'] ?? 1),
                    ],
                ],
            ]],
        ];
    }

    $sarif = [
        '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
        'version' => '2.1.0',
        'runs' => [[
            'tool' => ['driver' => [
                'name' => 'Psalm taint analysis',
                'informationUri' => 'https://psalm.dev/docs/security_analysis/',
                'rules' => array_values($rules),
            ]],
            'results' => $results,
        ]],
    ];
    file_put_contents($output, json_encode($sarif, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    fwrite(STDOUT, sprintf("%d taint finding(s)\n", count($results)));

    return 0;
}

/**
 * @param list<string> $arguments
 */
function issues(array $arguments): int
{
    $options = ['repo' => '', 'sha' => '', 'root' => '.', 'audit' => '', 'max' => '10'];
    $dryRun = false;
    $files = [];
    for ($i = 0; $i < count($arguments); $i++) {
        $argument = $arguments[$i];
        if ($argument === '--dry-run') {
            $dryRun = true;
        } elseif (str_starts_with($argument, '--') && array_key_exists(substr($argument, 2), $options)) {
            $options[substr($argument, 2)] = $arguments[++$i] ?? '';
        } else {
            $files[] = $argument;
        }
    }
    if ($options['repo'] === '' || $options['sha'] === '') {
        return usage();
    }

    $findings = [];
    foreach ($files as $file) {
        array_push($findings, ...sarifFindings($file, $options['root']));
    }
    if ($options['audit'] !== '' && is_file($options['audit'])) {
        array_push($findings, ...auditFindings($options['audit']));
    }

    $high = array_values(array_filter($findings, static fn (array $finding): bool => $finding['severity'] >= HIGH));
    $unique = [];
    foreach ($high as $finding) {
        $unique[$finding['fingerprint']] ??= $finding;
    }
    fwrite(STDOUT, sprintf("%d finding(s), %d high or critical\n", count($findings), count($unique)));

    $known = $dryRun ? [] : knownFingerprints($options['repo']);
    $new = array_values(array_filter($unique, static fn (array $finding): bool => !isset($known[$finding['fingerprint']])));
    if ($new === []) {
        fwrite(STDOUT, "No new high or critical findings.\n");

        return 0;
    }

    $issues = count($new) > max(1, (int) $options['max'])
        ? [summaryIssue($new, $options['repo'], $options['sha'])]
        : array_map(static fn (array $finding): array => findingIssue($finding, $options['repo'], $options['sha']), $new);

    if ($dryRun) {
        foreach ($issues as $issue) {
            fwrite(STDOUT, "\n=== " . $issue['title'] . "\n" . $issue['body'] . "\n");
        }

        return 0;
    }

    run(['gh', 'label', 'create', LABEL, '--repo', $options['repo'], '--color', 'B60205',
        '--description', 'Found by the automatic security scan', '--force']);
    foreach ($issues as $issue) {
        run(['gh', 'issue', 'create', '--repo', $options['repo'], '--title', $issue['title'],
            '--body', $issue['body'], '--label', LABEL]);
        fwrite(STDOUT, 'Created: ' . $issue['title'] . "\n");
    }

    return 0;
}

/**
 * @return list<array{tool: string, rule: string, severity: float, message: string, path: string, line: int, fingerprint: string, help: string}>
 */
function sarifFindings(string $file, string $root): array
{
    $sarif = readJson($file);
    $findings = [];
    foreach (is_array($sarif['runs'] ?? null) ? $sarif['runs'] : [] as $run) {
        $driver = $run['tool']['driver'] ?? [];
        $tool = (string) ($driver['name'] ?? 'scanner');
        $rules = [];
        foreach (array_merge($driver['rules'] ?? [], ...array_map(
            static fn (array $extension): array => $extension['rules'] ?? [],
            $run['tool']['extensions'] ?? []
        )) as $rule) {
            $rules[(string) ($rule['id'] ?? '')] = $rule;
        }
        foreach ($run['results'] ?? [] as $result) {
            $ruleId = (string) ($result['ruleId'] ?? $result['rule']['id'] ?? 'unknown');
            $rule = $rules[$ruleId] ?? [];
            $location = $result['locations'][0]['physicalLocation'] ?? [];
            $path = (string) ($location['artifactLocation']['uri'] ?? '');
            $line = (int) ($location['region']['startLine'] ?? 0);
            $findings[] = [
                'tool' => $tool,
                'rule' => $ruleId,
                'severity' => sarifSeverity($result, $rule),
                'message' => trim((string) ($result['message']['text'] ?? $rule['shortDescription']['text'] ?? $ruleId)),
                'path' => $path,
                'line' => $line,
                'fingerprint' => fingerprint($tool, $ruleId, $path, sourceLine($root, $path, $line)),
                'help' => (string) ($rule['helpUri'] ?? ''),
            ];
        }
    }

    return $findings;
}

/**
 * The rule's security-severity (as set by CodeQL and the Psalm conversion); without it, the
 * level: "error" counts as high, "warning" as medium.
 *
 * @param array<mixed> $result
 * @param array<mixed> $rule
 */
function sarifSeverity(array $result, array $rule): float
{
    $severity = $result['properties']['security-severity'] ?? $rule['properties']['security-severity'] ?? null;
    if (is_numeric($severity)) {
        return (float) $severity;
    }

    return match ($result['level'] ?? $rule['defaultConfiguration']['level'] ?? 'warning') {
        'error' => HIGH,
        'warning' => 5.0,
        default => 2.0,
    };
}

/**
 * @return list<array{tool: string, rule: string, severity: float, message: string, path: string, line: int, fingerprint: string, help: string}>
 */
function auditFindings(string $file): array
{
    $findings = [];
    foreach (readJson($file)['advisories'] ?? [] as $package => $advisories) {
        foreach (is_array($advisories) ? $advisories : [] as $advisory) {
            $id = (string) ($advisory['cve'] ?? '') !== '' ? (string) $advisory['cve'] : (string) ($advisory['advisoryId'] ?? '');
            $findings[] = [
                'tool' => 'composer audit',
                'rule' => $id,
                'severity' => match (strtolower((string) ($advisory['severity'] ?? ''))) {
                    'critical' => CRITICAL,
                    'high' => HIGH,
                    'medium' => 5.0,
                    'low' => 2.0,
                    // Unrated advisories are rare; better one issue too many.
                    default => HIGH,
                },
                'message' => sprintf('%s (%s): %s', (string) $package, (string) ($advisory['affectedVersions'] ?? ''), (string) ($advisory['title'] ?? '')),
                'path' => 'composer.lock',
                'line' => 0,
                'fingerprint' => fingerprint('composer audit', $id, (string) $package, ''),
                'help' => (string) ($advisory['link'] ?? ''),
            ];
        }
    }

    return $findings;
}

/**
 * Independent of the line number, so that moving code does not report a finding again.
 */
function fingerprint(string $tool, string $rule, string $path, string $code): string
{
    return substr(hash('sha256', implode("\0", [$tool, $rule, $path, preg_replace('/\s+/', ' ', trim($code))])), 0, 16);
}

function sourceLine(string $root, string $path, int $line): string
{
    $file = rtrim($root, '/') . '/' . $path;
    if ($line < 1 || !is_file($file)) {
        return '';
    }
    $lines = file($file, FILE_IGNORE_NEW_LINES);

    return is_array($lines) ? (string) ($lines[$line - 1] ?? '') : '';
}

/**
 * @return array<string, true>
 */
function knownFingerprints(string $repo): array
{
    $json = run(['gh', 'issue', 'list', '--repo', $repo, '--label', LABEL, '--state', 'all',
        '--limit', '1000', '--json', 'body']);
    $known = [];
    foreach (json_decode($json, true, flags: JSON_THROW_ON_ERROR) as $issue) {
        preg_match_all('/security-scan-fingerprint: ([0-9a-f]{16})/', (string) ($issue['body'] ?? ''), $matches);
        foreach ($matches[1] as $fingerprint) {
            $known[$fingerprint] = true;
        }
    }

    return $known;
}

/**
 * @param array{tool: string, rule: string, severity: float, message: string, path: string, line: int, fingerprint: string, help: string} $finding
 * @return array{title: string, body: string}
 */
function findingIssue(array $finding, string $repo, string $sha): array
{
    return [
        'title' => sprintf('Security: %s in %s', $finding['rule'], $finding['path']),
        'body' => implode("\n", [
            sprintf('The automatic security scan found a **%s** finding.', severityName($finding['severity'])),
            '',
            '| | |',
            '|---|---|',
            '| Tool | ' . $finding['tool'] . ' |',
            '| Rule | ' . ($finding['help'] !== '' ? '[' . $finding['rule'] . '](' . $finding['help'] . ')' : $finding['rule']) . ' |',
            '| Where | ' . location($finding, $repo, $sha) . ' |',
            '',
            '> ' . str_replace("\n", "\n> ", $finding['message']),
            '',
            'All findings: https://github.com/' . $repo . '/security/code-scanning',
            '',
            'Close this issue when it is fixed or not a real problem; the scan then does not report it again.',
            '',
            '<!-- security-scan-fingerprint: ' . $finding['fingerprint'] . ' -->',
        ]),
    ];
}

/**
 * @param list<array{tool: string, rule: string, severity: float, message: string, path: string, line: int, fingerprint: string, help: string}> $findings
 * @return array{title: string, body: string}
 */
function summaryIssue(array $findings, string $repo, string $sha): array
{
    $lines = [
        sprintf('The automatic security scan found %d new high or critical findings at once, so they are listed here instead of one issue each.', count($findings)),
        '',
    ];
    foreach ($findings as $finding) {
        $lines[] = sprintf('- **%s** %s (%s): %s', severityName($finding['severity']), $finding['rule'], $finding['tool'], location($finding, $repo, $sha));
    }
    $lines[] = '';
    $lines[] = 'All findings: https://github.com/' . $repo . '/security/code-scanning';
    $lines[] = '';
    foreach ($findings as $finding) {
        $lines[] = '<!-- security-scan-fingerprint: ' . $finding['fingerprint'] . ' -->';
    }

    return ['title' => sprintf('Security: %d new findings', count($findings)), 'body' => implode("\n", $lines)];
}

/**
 * @param array{path: string, line: int} $finding
 */
function location(array $finding, string $repo, string $sha): string
{
    $label = $finding['path'] . ($finding['line'] > 0 ? ':' . $finding['line'] : '');

    return sprintf('[%s](https://github.com/%s/blob/%s/%s%s)', $label, $repo, $sha, $finding['path'], $finding['line'] > 0 ? '#L' . $finding['line'] : '');
}

function severityName(float $severity): string
{
    return $severity >= CRITICAL ? 'critical' : ($severity >= HIGH ? 'high' : 'medium');
}

/**
 * @return array<mixed>
 */
function readJson(string $file): array
{
    $json = json_decode((string) file_get_contents($file), true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($json)) {
        throw new RuntimeException($file . ' is not a JSON object or list.');
    }

    return $json;
}

/**
 * Runs a command without a shell, so arguments are never interpreted.
 *
 * @param list<string> $command
 */
function run(array $command): string
{
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($process)) {
        throw new RuntimeException('Cannot run ' . $command[0]);
    }
    $output = (string) stream_get_contents($pipes[1]);
    $error = (string) stream_get_contents($pipes[2]);
    if (proc_close($process) !== 0) {
        throw new RuntimeException(implode(' ', array_slice($command, 0, 3)) . " failed:\n" . $error);
    }

    return $output;
}

exit(main(array_values(array_map(strval(...), $_SERVER['argv'] ?? []))));
