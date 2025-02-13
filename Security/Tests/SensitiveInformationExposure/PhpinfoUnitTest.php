<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\SensitiveInformationExposure;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

class PhpinfoUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [
            3 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
