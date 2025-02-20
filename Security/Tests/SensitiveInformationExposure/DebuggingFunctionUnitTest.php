<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\SensitiveInformationExposure;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class DebuggingFunctionUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [];
    }

    protected function getWarningList(): array
    {
        return [
            3 => 1,
            4 => 1,
            5 => 1,
            6 => 1,
        ];
    }
}
