<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\Injection;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function in_array;

use const T_OPEN_PARENTHESIS;
use const T_STRING;

final class OsInjectionSniff implements Sniff
{
    const array DANGEROUS_FUNCTIONS = ['exec', 'passthru', 'proc_open', 'popen', 'shell_exec', 'system', 'pcntl_exec'];

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
                'Passing user input to ' . $tokens[$stackPtr]['content'] . ' can lead to OS command injection (CWE-78)',
                $stackPtr,
                'FoundWithUserInput'
            );

            return;
        }

        if ($this->userInputDetector->containsVariableInput($phpcsFile, $start)) {
            $phpcsFile->addWarning(
                'Passing variable data to ' . $tokens[$stackPtr]['content'] . ' can lead to OS command injection (CWE-78) if it contains user input',
                $stackPtr,
                'FoundWithVariableInput'
            );
        }
    }
}
