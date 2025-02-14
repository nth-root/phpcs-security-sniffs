<?php

declare(strict_types=1);

require_once $_GET['file'];

$target = $_GET['host'];

shell_exec('ping ' . $target);

echo file_get_contents($_GET['file']);

$url = "http://example.com";

$hash = sha1($user->password);
