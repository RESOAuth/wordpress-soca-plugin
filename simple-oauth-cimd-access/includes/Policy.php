<?php
namespace SOCA;
final class Policy {
    public static function domain(string $s): string {
        $s = strtolower(trim($s));
        Support::need(strlen($s) <= 253 && str_contains($s, '.') && !Support::localHost($s) &&
            (bool) preg_match('/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $s),
            'domain', 'Use an exact public ASCII domain (IDNs must use punycode), without @, wildcard, URL or trailing dot.');
        return $s;
    }
    public static function email(string $s): string {
        $s = trim($s);
        Support::need(strlen($s) <= 254 && (bool) filter_var($s, FILTER_VALIDATE_EMAIL) &&
            (bool) preg_match('/^[\x21-\x7e]+$/D', $s), 'email', 'Enter a valid ASCII email address.');
        [$local,$domain] = explode('@', $s, 2);
        return strtolower($local) . '@' . self::domain($domain);
    }
    public static function entries(string $text, bool $email): array {
        Support::need(strlen($text) <= 32000, 'policy_size', 'Too many policy entries.');
        $out = [];
        foreach (preg_split('/[\s,;]+/', trim($text), -1, PREG_SPLIT_NO_EMPTY) as $value) {
            $out[] = $email ? self::email($value) : self::rule($value);
        }
        $out = array_values(array_unique($out));
        Support::need(count($out) <= 200, 'policy_size', 'Limit each list to 200 entries.');
        sort($out, SORT_STRING); return $out;
    }
    public static function rule(string $value): string {
        $value = strtolower(trim($value));
        return str_starts_with($value, '*.') ? '*.' . self::domain(substr($value, 2)) : self::domain($value);
    }
    private static function matches(string $domain, array $rules): bool {
        $match = false;
        foreach ($rules as $rule) {
            $rule = self::rule($rule);
            $match = $match || (str_starts_with($rule, '*.') ? str_ends_with($domain, substr($rule, 1)) : $domain === $rule);
        }
        return $match;
    }
    public static function test(array $s, string $email, bool $verified): array {
        if (!$verified) { return [false, 'A verified email is required.']; }
        $email = self::email($email); $domain = explode('@', $email, 2)[1];
        if (in_array($email, $s['deny_emails'], true)) { return [false, 'Email deny rule wins.']; }
        $denyDomain = self::matches($domain, $s['deny_domains']);
        $allowDomain = self::matches($domain, $s['allow_domains']);
        if ($denyDomain) { return [false, 'Domain deny rule wins.']; }
        if ($s['unrestricted']) { return [true, 'Any verified email is allowed; no deny rule matched.']; }
        if (in_array($email, $s['allow_emails'], true)) { return [true, 'Email allow rule matches; no deny rule matched.']; }
        if ($allowDomain) { return [true, 'Domain allow rule matches; no deny rule matched.']; }
        if ($s['allow_emails'] || $s['allow_domains']) { return [false, 'Neither allowlist matched. Subdomains require an explicit rule or a leading *. rule.']; }
        return [false, 'No allowlist matched. Add a domain/email or enable Allow any verified email.'];
    }
}
