<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Injection;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class RemoteFileInclusionUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [
            3 => 1,
            5 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [
            7 => 1,
        ];
    }
}
