<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\CryptographicFailures;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class PasswordHashingUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [
            3 => 1,
            4 => 1,
            6 => 1,
            7 => 1,
            8 => 1,
            9 => 1,
            11 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
