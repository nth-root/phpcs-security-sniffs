<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\SensitiveInformationExposure;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Reports the use of phpinfo() function.
 */
final class PhpinfoSniff implements Sniff
{
    public function register(): array
    {
        return [T_STRING];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        if ($tokens[$stackPtr]['content'] === 'phpinfo') {
            $phpcsFile->addError('The phpinfo() function can expose sensitive information (CWE-200)', $stackPtr, 'Found');
        }
    }
}
