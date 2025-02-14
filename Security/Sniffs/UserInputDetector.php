<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Util\Tokens;

use function array_slice;
use function in_array;
use function range;

use const T_EQUAL;
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
        $tokens = $file->getTokens();

        if ($tokens[$start]['code'] === T_OPEN_PARENTHESIS) {
            $closingParenthesis = $tokens[$start]['parenthesis_closer'];

            $tokenPositions = range($start + 1, $closingParenthesis - 1);
        } else {
            $tokenPositions = range($start, $file->findEndOfStatement($start) - 1);
        }

        foreach ($tokenPositions as $token) {
            if ($this->isTainted($file, $token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns true if the token at the given position contains user input.
     */
    public function isTainted(File $file, int $tokenPosition): bool
    {
        $tokens = $file->getTokens();
        $token = $tokens[$tokenPosition];

        if ($token['code'] === T_VARIABLE && in_array($token['content'], self::SUPERGLOBALS, true)) {
            return true;
        }

        if ($token['code'] === T_VARIABLE) {
            $variableName = $token['content'];

            $definition = $this->getVariableDefinition($file, $tokenPosition, $variableName);

            if (!$definition) {
                // Cannot find the definition of the variable
                return false;
            }

            $value = $file->findNext(T_VARIABLE, $definition + 1);

            return $this->isTainted($file, $value);
        }

        return false;
    }

    private function getVariableDefinition(File $file, int $tokenPosition, string $name): int|false
    {
        $tokens = $file->getTokens();

        while ($tokenPosition = $file->findPrevious(T_VARIABLE, $tokenPosition - 1, null, false, $name)) {
            $nextToken = $file->findNext(Tokens::$emptyTokens, $tokenPosition + 1, null, true, null, true);
            $nextToken = $tokens[$nextToken];

            if ($nextToken['code'] === T_EQUAL) {
                return $tokenPosition;
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
}
