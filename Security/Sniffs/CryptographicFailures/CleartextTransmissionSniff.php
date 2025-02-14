<?php

declare(strict_types=1);

namespace NthRoot\PhpSecuritySniffs\Security\Sniffs\CryptographicFailures;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

use function str_contains;
use function strtoupper;

use const T_CONSTANT_ENCAPSED_STRING;
use const T_HEREDOC;

final class CleartextTransmissionSniff implements Sniff
{
    const array CLEARTEXT_PROTOCOLS = ['http', 'ftp'];

    public function register(): array
    {
        return [T_CONSTANT_ENCAPSED_STRING, T_HEREDOC, T_NOWDOC];
    }

    public function process(File $phpcsFile, $stackPtr): void
    {
        $tokens = $phpcsFile->getTokens();

        $stringToken = $tokens[$stackPtr];

        $content = $stringToken['content'];

        foreach (self::CLEARTEXT_PROTOCOLS as $protocol) {
            if (str_contains($content, $protocol . '://')) {
                $phpcsFile->addError(
                    sprintf(
                        "Cleartext transmission of data over %s is a security risk (CWE-319)",
                        strtoupper($protocol)
                    ),
                    $stackPtr,
                    'Found'
                );
            }
        }
    }
}
