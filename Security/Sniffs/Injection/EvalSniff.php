<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\Injection;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use const T_OPEN_PARENTHESIS;

final class EvalSniff implements Sniff
{
    private UserInputDetector $userInputDetector;

    public function __construct()
    {
        $this->userInputDetector = new UserInputDetector();
    }

    public function register(): array
    {
        return [T_EVAL];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $openParenthesis = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);

        if ($this->userInputDetector->containsUserInput($phpcsFile, $openParenthesis)) {
            $phpcsFile->addError(
                'Passing user input to eval() can lead to eval injection and remote code execution (CWE-95)',
                $stackPtr,
                'FoundWithUserInput'
            );

            return;
        }

        if ($this->userInputDetector->containsVariableInput($phpcsFile, $openParenthesis)) {
            $phpcsFile->addError(
                'Passing variable input to eval() can lead to eval injection and remote code execution (CWE-95)',
                $stackPtr,
                'FoundWithVariableInput'
            );

            return;
        }

        $phpcsFile->addWarning('The eval() function can be dangerous and should be avoided', $stackPtr, 'Found');
    }
}
