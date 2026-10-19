<?php
namespace SOCA\Security;

use Psalm\Plugin\PluginEntryPointInterface;
use Psalm\Plugin\RegistrationInterface;
use SimpleXMLElement;

final class PsalmTaintPlugin implements PluginEntryPointInterface {
    public function __invoke(RegistrationInterface $registration, ?SimpleXMLElement $config = null): void {
        // Register after the WordPress plugin so our taint annotations override
        // its type-only stubs instead of being silently replaced by them.
        $registration->addStubFile(__DIR__ . '/wordpress-taint.phpstub');
    }
}
