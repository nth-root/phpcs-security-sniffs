<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Injection;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class SqlInjectionUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [
            7 => 1,
            11 => 1,
            12 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
