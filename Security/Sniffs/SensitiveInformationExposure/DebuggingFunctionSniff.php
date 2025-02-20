<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\SensitiveInformationExposure;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function in_array;
use function sprintf;

use const T_STRING;

final class DebuggingFunctionSniff implements Sniff
{
    private const array DEBUGGING_FUNCTIONS = ['var_dump', 'dump', 'dd', 'print_r'];

    public function register(): array
    {
        return [T_STRING];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        if (!in_array($tokens[$stackPtr]['content'], self::DEBUGGING_FUNCTIONS, true)) {
            return;
        }

        $phpcsFile->addWarning(
            sprintf(
                'Leaving debugging functions such as %s() in the code might lead to sensitive data exposure (CWE-489)',
                $tokens[$stackPtr]['content']
            ),
            $stackPtr,
            'Found'
        );
    }
}
