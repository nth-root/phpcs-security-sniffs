<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\Injection;

use NthRoot\PhpSecuritySniffs\Security\Sniffs\UserInputDetector;
use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function in_array;

use const T_OBJECT_OPERATOR;
use const T_OPEN_PARENTHESIS;
use const T_STRING;
use const T_VARIABLE;

final class SqlInjectionSniff implements Sniff
{
    private const array FUNCTIONS = [
        'mysqli_query',
        'mysqli_real_query',
        'mysqli_multi_query',
    ];

    private const array METHODS = [
        'query',
        'prepare',
    ];

    private UserInputDetector $userInputDetector;

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

        $function = $tokens[$stackPtr]['content'];

        if ($objectOperator = $phpcsFile->findPrevious(T_OBJECT_OPERATOR, $stackPtr - 1, null, false, null, true)) {
            $object = $phpcsFile->findPrevious([T_STRING, T_VARIABLE], $objectOperator - 1, null, false, null, true);
            $object = $tokens[$object]['content'];
        }

        if ($objectOperator === false && !in_array($function, self::FUNCTIONS, true)) {
            return;
        }

        if ($objectOperator !== false && !in_array($function, self::METHODS, true)) {
            return;
        }

        $openParenthesis = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);

        if ($this->userInputDetector->containsUserInput($phpcsFile, $openParenthesis)) {
            $phpcsFile->addError(
                sprintf(
                    'Passing user input to %s() can lead to SQL injection (CWE-89)',
                    isset($object) ? $object . '->' . $function : $function
                ),
                $stackPtr,
                'FoundWithUserInput'
            );
        }
    }
}
