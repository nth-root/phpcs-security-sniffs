<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\Injection;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

final class RemoteFileInclusionSniff implements Sniff
{
    private UserInputDetector $userInputDetector;

    public function __construct()
    {
        $this->userInputDetector = new UserInputDetector();
    }

    public function register(): array
    {
        return [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        $start = $phpcsFile->findNext(Tokens::$emptyTokens, $stackPtr, null, true, null, true);

        if ($this->userInputDetector->containsUserInput($phpcsFile, $start)) {
            $phpcsFile->addError(
                'Passing user input to ' . $tokens[$stackPtr]['content'] . '() can lead to remote file inclusion (CWE-98)',
                $start,
                'FoundWithUserInput'
            );

            return;
        }

        if ($this->userInputDetector->containsVariableInput($phpcsFile, $start)) {
            $phpcsFile->addWarning(
                'Passing variable input to ' . $tokens[$stackPtr]['content'] . '() can lead to remote file inclusion (CWE-98) if it contains user input',
                $start,
                'FoundWithVariableInput'
            );
        }
    }
}
