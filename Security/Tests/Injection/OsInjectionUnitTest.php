<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Injection;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class OsInjectionUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(string $filename = ''): array
    {
        if ($filename === 'OsInjectionUnitTest.Indirect.inc') {
            return [
                7 => 1,
            ];
        }

        return [
            3 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
