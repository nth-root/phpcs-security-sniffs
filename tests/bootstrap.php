<?php

declare(strict_types=1);

if (defined('PHP_CODESNIFFER_IN_TESTS') === false) {
    define('PHP_CODESNIFFER_IN_TESTS', true);
}

$GLOBALS['PHP_CODESNIFFER_SNIFF_CODES'] = [];

require_once __DIR__ . '/../vendor/squizlabs/php_codesniffer/autoload.php';
require_once __DIR__ . '/../vendor/squizlabs/php_codesniffer/tests/bootstrap.php';

