<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Injection;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

final class CrossSiteScriptingUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList(string $filename = ''): array
    {
        return match ($filename) {
            'CrossSiteScriptingUnitTest.inc' => [
                3 => 1,
                4 => 1,
                6 => 1,
                7 => 1,
                11 => 1,
            ],
            'CrossSiteScriptingUnitTest.ShortEchoTag.inc' => [
                1 => 1,
            ],
        };
    }

    protected function getWarningList(): array
    {
        return [];
    }
}
