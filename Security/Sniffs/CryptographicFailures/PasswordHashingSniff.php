<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\CryptographicFailures;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function array_keys;
use function array_slice;
use function in_array;
use function sprintf;
use function str_contains;
use function strtolower;

use const T_CONSTANT_ENCAPSED_STRING;
use const T_OPEN_PARENTHESIS;
use const T_STRING;
use const T_VARIABLE;

/**
 * This sniff checks for the use of insecure password hashing algorithms.
 */
final class PasswordHashingSniff implements Sniff
{
    private const array SUSPICIOUS_VARIABLE_NAMES = ['pass', 'pwd'];

    private const array ALGORITHMS = ['md5', 'sha1'];

    private const array ENCODING_ALGORITHMS = [
        'base64_encode' => 'Base64',
        'base64_decode' => 'Base64',
    ];

    public function register(): array
    {
        return [T_STRING];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        $functionName = $tokens[$stackPtr]['content'];

        if (!in_array($functionName, [...self::ALGORITHMS, ...array_keys(self::ENCODING_ALGORITHMS), 'hash'], true)) {
            return;
        }

        if (!$this->containsPasswordArgument($phpcsFile, $stackPtr)) {
            return;
        }

        if ($functionName === 'hash') {
            $phpcsFile->addError(
                'The hash() function is not safe for password hashing (CWE-916), use password_hash() for hashing passwords',
                $stackPtr,
                'Found'
            );

            return;
        }

        if (in_array($functionName, array_keys(self::ENCODING_ALGORITHMS), true)) {
            $phpcsFile->addError(
                sprintf(
                    'The %s encoding algorithm is not safe for storing passwords (CWE-261), use one-way hashing with password_hash()',
                    self::ENCODING_ALGORITHMS[$functionName]
                ),
                $stackPtr,
                'Found'
            );

            return;
        }

        $phpcsFile->addError(
            sprintf(
                'The %s algorithm is not safe for password hashing (CWE-916), use password_hash() for hashing passwords',
                $functionName
            ),
            $stackPtr,
            'Found'
        );
    }

    private function containsPasswordArgument(File $phpcsFile, int $stackPtr): bool
    {
        $tokens = $phpcsFile->getTokens();

        $openParenthesis = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr, null, false, null, true);
        $closingParenthesis = $tokens[$openParenthesis]['parenthesis_closer'];

        $start = $openParenthesis;

        $argumentTokens = array_slice($tokens, $start + 1, $closingParenthesis - $start - 1);

        foreach ($argumentTokens as $token) {
            if (!in_array($token['code'], [T_VARIABLE, T_STRING, T_CONSTANT_ENCAPSED_STRING], true)) {
                continue;
            }

            foreach (self::SUSPICIOUS_VARIABLE_NAMES as $suspiciousVariableName) {
                if (str_contains(strtolower($token['content']), $suspiciousVariableName)) {
                    return true;
                }
            }
        }

        return false;
    }
}
