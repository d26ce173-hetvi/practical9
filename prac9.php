
<?php
$message = "";
$messageType = "";

$conn = new mysqli("localhost", "root", "", "studenthub");

if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$conn->set_charset("utf8mb4");

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirm_password = $_POST["confirm_password"] ?? "";

    // Backend validation
    if ($username === "" || $email === "" ||
        $password === "" || $confirm_password === "") {

        $message = "All fields are required.";
        $messageType = "error";

    } elseif (!preg_match("/^[a-zA-Z0-9_]{3,30}$/", $username)) {

        $message = "Username must be 3-30 characters and contain only letters, numbers, or underscores.";
        $messageType = "error";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        $message = "Please enter a valid email address.";
        $messageType = "error";

    } elseif (strlen($password) < 8) {

        $message = "Password must contain at least 8 characters.";
        $messageType = "error";

    } elseif ($password !== $confirm_password) {

        $message = "Passwords do not match.";
        $messageType = "error";

    } else {

        // Check duplicate username or email
        $stmt = $conn->prepare(
            "SELECT user_id FROM users
             WHERE username = ? OR email = ?"
        );

        if (!$stmt) {
            $message = "Query preparation failed.";
            $messageType = "error";
        } else {
            $stmt->bind_param("ss", $username, $email);
            $stmt->execute();
            $stmt->store_result();

            $duplicate = ($stmt->num_rows > 0);

            $stmt->close();

            if ($duplicate) {
                $message = "Username or email already exists.";
                $messageType = "error";
            } else {

                // Securely hash the password
                $password_hash = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );

                // Insert new user
                $insertStmt = $conn->prepare(
                    "INSERT INTO users
                     (username, email, password_hash)
                     VALUES (?, ?, ?)"
                );

                if (!$insertStmt) {
                    $message = "Insert query preparation failed.";
                    $messageType = "error";
                } else {
                    $insertStmt->bind_param(
                        "sss",
                        $username,
                        $email,
                        $password_hash
                    );

                    if ($insertStmt->execute()) {
                        $message = "Registration successful!";
                        $messageType = "success";
                    } else {
                        $message = "Registration failed. Please try again.";
                        $messageType = "error";
                    }

                    // Close the insert statement only once
                    $insertStmt->close();
                }
            }
        }
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Practical 9 - User Registration</title>

    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f2f4f8;
            margin: 0;
            padding: 30px 15px;
        }

        .container {
            max-width: 420px;
            margin: auto;
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 12px #cccccc;
        }

        h2 {
            text-align: center;
            color: #243b55;
        }

        label {
            display: block;
            margin-top: 15px;
            font-weight: bold;
        }

        input {
            box-sizing: border-box;
            width: 100%;
            padding: 10px;
            margin-top: 6px;
            border: 1px solid #bbb;
            border-radius: 5px;
        }

        button {
            width: 100%;
            margin-top: 22px;
            padding: 12px;
            border: none;
            border-radius: 5px;
            background: #2457a7;
            color: white;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #173d78;
        }

        .message {
            padding: 12px;
            margin-bottom: 15px;
            border-radius: 5px;
            text-align: center;
        }

        .success {
            background: #d8f3dc;
            color: #176b35;
        }

        .error {
            background: #ffe0e0;
            color: #a00000;
        }
    </style>
</head>

<body>
<div class="container">

    <h2>User Registration</h2>

    <?php if ($message !== ""): ?>
        <div class="message
            <?php echo htmlspecialchars($messageType); ?>">
            <?php echo htmlspecialchars($message); ?>
        </div>
    <?php endif; ?>

    <form method="POST" action="prac9.php"
          onsubmit="return validateForm()">

        <label for="username">Username</label>
        <input type="text" id="username" name="username"
               minlength="3" maxlength="30"
               pattern="[A-Za-z0-9_]{3,30}"
               title="Use 3-30 letters, numbers, or underscores"
               value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>"
               required>

        <label for="email">Email</label>
        <input type="email" id="email" name="email"
               value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>"
               required>

        <label for="password">Password</label>
        <input type="password" id="password" name="password"
               minlength="8" required>

        <label for="confirm_password">Confirm Password</label>
        <input type="password" id="confirm_password"
               name="confirm_password" minlength="8" required>

        <button type="submit">Register</button>
    </form>

</div>

<script>
function validateForm() {
    const password = document.getElementById("password").value;
    const confirmPassword =
        document.getElementById("confirm_password").value;

    if (password.length < 8) {
        alert("Password must contain at least 8 characters.");
        return false;
    }

    if (password !== confirmPassword) {
        alert("Passwords do not match.");
        return false;
    }

    return true;
}
</script>

</body>
</html>
