<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs;

use PHP_CodeSniffer\Files\File;

use function array_slice;
use function in_array;

use const T_OPEN_PARENTHESIS;
use const T_VARIABLE;

final class UserInputDetector
{
    private const array SUPERGLOBALS = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$_ENV'];

    public function containsVariableInput(File $file, int $start): bool
    {
        $tokens = $this->getArgumentTokens($file, $start);

        foreach ($tokens as $token) {
            if ($token['code'] === T_VARIABLE) {
                return true;
            }
        }

        return false;
    }

    public function containsUserInput(File $file, int $start): bool
    {
        $tokens = $this->getArgumentTokens($file, $start);

        foreach ($tokens as $token) {
            if ($this->isUserInput($token)) {
                return true;
            }
        }

        return false;
    }

    private function getArgumentTokens(File $file, int $start): array
    {
        $tokens = $file->getTokens();

        if ($tokens[$start]['code'] === T_OPEN_PARENTHESIS) {
            $closingParenthesis = $tokens[$start]['parenthesis_closer'];

            return array_slice($tokens, $start + 1, $closingParenthesis - $start);
        }

        $endOfStatement = $file->findEndOfStatement($start);

        return array_slice($tokens, $start, $endOfStatement - $start);
    }

    /**
     * @param array{code: int, content: string} $token
     */
    private function isUserInput(array $token): bool
    {
        if ($token['code'] !== T_VARIABLE) {
            return false;
        }

        if (in_array($token['content'], self::SUPERGLOBALS, true)) {
            return true;
        }

        return false;
    }
}
