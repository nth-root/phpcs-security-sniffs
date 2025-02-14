<?php

$target = $_GET['target'];

shell_exec('ping ' . $target);
