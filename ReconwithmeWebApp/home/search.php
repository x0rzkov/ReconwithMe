<?php
require('../db/dbconnect.php');
$search=$_POST['q'];
if (mysqli_connect_errno()) {
  echo "Failed to connect to MySQL: " . mysqli_connect_error();
  exit();
}

$sql = "SELECT * FROM Vulnerabilities WHERE url='$search'";

if ($result = mysqli_query($connectivity, $sql)) {
  // Fetch one and one row
  while ($row = mysqli_fetch_row($result)) {
    echo $row[2]."<br>";
  }
  mysqli_free_result($result);
}

mysqli_close($connectivity);
?>
