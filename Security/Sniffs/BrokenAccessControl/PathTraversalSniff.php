<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\BrokenAccessControl;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function in_array;

use const T_OPEN_PARENTHESIS;
use const T_STRING;

final class PathTraversalSniff implements Sniff
{
    const array DANGEROUS_FUNCTIONS = ['fopen', 'file_get_contents'];

    protected UserInputDetector $userInputDetector;

    public function __construct()
    {
        $this->userInputDetector = new UserInputDetector();
    }

    public function register(): array
    {
        return [T_STRING];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        if (!in_array($tokens[$stackPtr]['content'], self::DANGEROUS_FUNCTIONS, true)) {
            return;
        }

        $start = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);

        if ($this->userInputDetector->containsUserInput($phpcsFile, $start)) {
            $phpcsFile->addError(
                sprintf(
                    "Passing user input to %s() can lead to path traversal attacks (CWE-22)",
                    $tokens[$stackPtr]['content']
                ),
                $stackPtr,
                'FoundWithUserInput'
            );

            return;
        }

        if ($this->userInputDetector->containsVariableInput($phpcsFile, $start)) {
            $phpcsFile->addWarning(
                sprintf(
                    "Passing variable data to %s() can lead to path traversal attacks (CWE-22) if it contains user input",
                    $tokens[$stackPtr]['content']
                ),
                $stackPtr,
                'FoundWithVariableInput'
            );
        }
    }
}
