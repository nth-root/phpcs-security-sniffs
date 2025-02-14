<?php

$hash = md5($password);
$hash = sha1($PassWord);

$hash = hash('sha512', $pwd);
$hash = hash('sha512/256', $_POST['password']);
$hash = hash('sha512/256', $user->password);
$hash = hash('sha512/256', $user->getPassword());

$hash = base64_encode($userPass);

// Using the password_hash function is safe
password_hash($password, PASSWORD_DEFAULT);

// Do not report other arguments passed to hashing functions
$hash = md5($filename);
$hash = md5('foo');
