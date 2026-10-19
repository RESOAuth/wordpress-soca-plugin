<?php
// Run scanners against static fixtures. Never execute the vulnerable fixtures.
declare(strict_types=1);

function scan(array $command, array $expectedExits): array {
    $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => STDERR], $pipes);
    if (!is_resource($process)) { throw new RuntimeException('Could not start scanner.'); }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $status = proc_close($process);
    if (!in_array($status, $expectedExits, true)) {
        throw new RuntimeException("Scanner failed with exit $status:\n$output");
    }
    return json_decode($output, true, 512, JSON_THROW_ON_ERROR);
}

chdir(__DIR__ . '/../../tools/security');
$scanner = $argv[1] ?? '';
if ($scanner === 'psalm') {
    $issues = scan([PHP_BINARY, 'vendor/bin/psalm', '--config=psalm-fixtures.xml', '--taint-analysis', '--no-cache', '--no-progress', '--output-format=json'], [2]);
    $types = [];
    $htmlLines = [];
    $sqlLines = [];
    foreach ($issues as $issue) {
        if (basename($issue['file_name']) !== 'unsafe.php') {
            throw new RuntimeException('Unexpected Psalm finding in safe fixture: ' . json_encode($issue));
        }
        $types[] = $issue['type'];
        if ($issue['type'] === 'TaintedHtml') { $htmlLines[] = $issue['line_from']; }
        if ($issue['type'] === 'TaintedSql') { $sqlLines[] = $issue['line_from']; }
    }
    foreach (['TaintedHtml', 'TaintedSql', 'TaintedShell'] as $type) {
        if (!in_array($type, $types, true)) { throw new RuntimeException("Psalm failed to detect $type."); }
    }
    if (count(array_unique($htmlLines)) !== 4) {
        throw new RuntimeException('Psalm must detect raw output, sanitized-but-unescaped output, URL escaping in a database context, and unescaped HTTP response output.');
    }
    if (count(array_unique($sqlLines)) !== 2) {
        throw new RuntimeException('Psalm must detect both raw SQL interpolation and request-controlled prepare templates.');
    }
} elseif ($scanner === 'phpcs') {
    $report = scan([PHP_BINARY, 'vendor/bin/phpcs', '--standard=phpcs.xml', '--report=json', '../../tests/security/phpcs'], [1, 2, 3]);
    $sources = [];
    foreach ($report['files'] as $file => $result) {
        if (basename($file) !== 'unsafe.php' && $result['messages']) {
            throw new RuntimeException('Unexpected WordPressCS finding in safe fixture: ' . json_encode($result));
        }
        foreach ($result['messages'] as $message) { $sources[] = $message['source']; }
    }
    foreach (['WordPress.Security.EscapeOutput', 'WordPress.Security.ValidatedSanitizedInput', 'WordPress.Security.NonceVerification', 'WordPress.DB.PreparedSQL'] as $sniff) {
        if (!array_filter($sources, static fn(string $source): bool => str_starts_with($source, $sniff . '.'))) {
            throw new RuntimeException("WordPressCS failed to detect $sniff.");
        }
    }
} else {
    throw new InvalidArgumentException('Usage: php tests/security/check.php <psalm|phpcs>');
}
echo "$scanner: unsafe fixtures detected; safe fixtures passed.\n";
