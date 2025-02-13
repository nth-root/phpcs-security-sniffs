<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs;

use function array_slice;
use function in_array;

use const T_VARIABLE;

final class UserInputDetector
{
    private const array SUPERGLOBALS = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER', '$_ENV'];

    /**
     * @param array<array{code: int, content: string}> $tokens
     */
    public function containsVariableInput(array $tokens, int $openingParenthesis): bool
    {
        $tokens = $this->getArgumentTokens($tokens, $openingParenthesis);

        foreach ($tokens as $token) {
            if ($token['code'] === T_VARIABLE) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<array{code: int, content: string}> $tokens
     */
    public function containsUserInput(array $tokens, int $openingParenthesis): bool
    {
        $tokens = $this->getArgumentTokens($tokens, $openingParenthesis);

        foreach ($tokens as $token) {
            if ($this->isUserInput($token)) {
                return true;
            }
        }

        return false;
    }

    private function getArgumentTokens(array $tokens, int $openingParenthesis): array
    {
        $closingParenthesis = $tokens[$openingParenthesis]['parenthesis_closer'];

        return array_slice($tokens, $openingParenthesis + 1, $closingParenthesis - $openingParenthesis);
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
