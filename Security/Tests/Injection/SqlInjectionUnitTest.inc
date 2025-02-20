<?php

$id = $_GET['id'];

$query = 'SELECT * FROM users WHERE id = ' . $id;

mysqli_query($query);

$pdo = new PDO('');

$statement = $pdo->prepare($query);
$statement = $pdo->query($query);
