<?php
// Deliberately vulnerable PHP (test fixture, never deploy).
echo $_GET['name'];                                   // reflected XSS
include($_GET['page'] . '.php');                      // file inclusion
$row = mysqli_query($conn, "SELECT * FROM u WHERE id=" . $_GET['id']); // SQL injection
system($_GET['cmd']);                                 // command injection
$hash = md5($_POST['password']);                      // weak hash
