<?php

declare(strict_types=1);

require_once $_GET['file'];

shell_exec('ping ' . $_GET['host']);

echo file_get_contents($_GET['file']);

$url = "http://example.com";

$hash = sha1($user->password);
