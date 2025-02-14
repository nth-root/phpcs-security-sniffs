<?php

$target = $_GET['host'];

$foo = $target . ' foo';

shell_exec('ping ' . $foo);
