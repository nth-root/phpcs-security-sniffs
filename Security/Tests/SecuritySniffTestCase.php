<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests;

use PHP_CodeSniffer\Tests\Standards\AbstractSniffUnitTest;

abstract class SecuritySniffTestCase extends AbstractSniffUnitTest
{
    protected function setUp(): void
    {
        $this->standardsDir = __DIR__ . '/../';
        $this->testsDir     = __DIR__ . '/';
    }

    abstract protected function getErrorList(): array;

    abstract protected function getWarningList(): array;
}
