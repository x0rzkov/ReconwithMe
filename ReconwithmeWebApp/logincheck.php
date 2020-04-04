<?php
if (isset($_POST['login'])){
		require('db/dbconnect.php');
    $username = mysqli_real_escape_string($connectivity, $_POST['username']);
    $password = mysqli_real_escape_string($connectivity, $_POST['password']);
    $query = "SELECT * FROM user WHERE username='$username' AND password='$password'";
    $results = mysqli_query($connectivity, $query);
    if (mysqli_num_rows($results) == 1) {
    	session_start();
		$row=mysqli_fetch_assoc($results);
    	$_SESSION['ID'] = $row['ID'];
    	header('location: /ReconwithMe/home');
    	}
      else {
        header('location: login.php?id=pass_error');
      }

}
?>
