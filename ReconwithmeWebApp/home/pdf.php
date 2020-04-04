<?php
$id=$_GET['id'];
echo $id;
require('../db/dbconnect.php');
if (mysqli_connect_errno()) {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  exit();
}
$sql = "SELECT * FROM Vulnerabilities WHERE id=$id";
echo $sql;
?>
