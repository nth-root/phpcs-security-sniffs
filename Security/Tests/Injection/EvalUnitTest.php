<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Tests\Injection;

use NthRoot\PhpSecuritySniffs\Security\Tests\SecuritySniffTestCase;

use function in_array;

class EvalUnitTest extends SecuritySniffTestCase
{
    protected function getErrorList($testFile = ''): array
    {
        if (in_array(
            $testFile,
            ['EvalUnitTest.WithUserInput.inc', 'EvalUnitTest.WithConcatenatedUserInput.inc'],
            true
        )) {
            return [
                3 => 1,
            ];
        }

        return [];
    }

    protected function getWarningList($testFile = ''): array
    {
        if ($testFile === 'EvalUnitTest.inc') {
            return [
                3 => 1,
            ];
        }

        return [];
    }
}
