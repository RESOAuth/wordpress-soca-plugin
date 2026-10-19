<?php
// Private namespace prevents dependency collisions with other WordPress plugins.
spl_autoload_register(static function (string $class): void {
    $prefix = 'SOCA\\Vendor\\JWT\\';
    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/php-jwt/src/' . substr($class, strlen($prefix)) . '.php';
        if (is_file($file)) { require_once $file; }
    }
});
