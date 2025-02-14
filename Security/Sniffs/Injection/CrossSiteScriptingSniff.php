<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\Injection;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

use const T_ECHO;
use const T_EXIT;
use const T_OPEN_TAG_WITH_ECHO;
use const T_PRINT;

final class CrossSiteScriptingSniff implements Sniff
{
    private UserInputDetector $userInputDetector;

    public function __construct()
    {
        $this->userInputDetector = new UserInputDetector();
    }

    public function register(): array
    {
        return [T_ECHO, T_PRINT, T_OPEN_TAG_WITH_ECHO, T_EXIT];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $start = $phpcsFile->findNext(Tokens::$emptyTokens, $stackPtr, null, true, null, true);

        if ($this->userInputDetector->containsUserInput($phpcsFile, $start)) {
            $phpcsFile->addError(
                'Outputting unsanitized user input can lead to cross-site scripting (CWE-79)',
                $start,
                'Found'
            );
        }
    }
}
