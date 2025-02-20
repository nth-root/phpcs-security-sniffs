<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\BrokenAccessControl;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class PathTraversalUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(): array
    {
        return [
            5 => 1,
        ];
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
