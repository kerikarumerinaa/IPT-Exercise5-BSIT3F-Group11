<?php
header('Content-Type: application/json');

$servername = "localhost";
$username = "root";
$password = "";
$dbname = "validation";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die(json_encode(["success" => false, "error" => "Connection failed: " . $conn->connect_error]));
}

// Get form data
$first_name = trim($_POST['firstName']);
$last_name = trim($_POST['lastName']);
$user_username = trim($_POST['username']);
$user_email = trim($_POST['email']);
$user_password = $_POST['password'];
$repeat_password = $_POST['repeatPassword'];
$birthdate = $_POST['birthdate'];

// Validate form data
$errors = [];

if (empty($first_name)) {
    $errors['firstName'] = "First name is required.";
}

if (empty($last_name)) {
    $errors['lastName'] = "Last name is required.";
}

if (empty($user_username)) {
    $errors['username'] = "Username is required.";
} elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $user_username)) {
    $errors['username'] = "Username can only contain letters, numbers, and underscores.";
}

if (empty($user_email)) {
    $errors['email'] = "Email is required.";
} elseif (!filter_var($user_email, FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = "Invalid email format.";
}

if (empty($user_password)) {
    $errors['password'] = "Password is required.";
} elseif (strlen($user_password) < 8) {
    $errors['password'] = "Password must be at least 8 characters long.";
}

if ($user_password !== $repeat_password) {
    $errors['repeatPassword'] = "Passwords do not match.";
}

if (empty($birthdate)) {
    $errors['birthdate'] = "Birthdate is required.";
} else {
    $age = date_diff(date_create($birthdate), date_create('today'))->y;
    if ($age < 18) {
        $errors['birthdate'] = "You must be at least 18 years old.";
    }
}

if (!empty($errors)) {
    echo json_encode(["success" => false, "errors" => $errors]);
    $conn->close();
    exit();
}

// Validate if email or username already exists
$sql_check = "SELECT * FROM infos WHERE email = ? OR username = ?";
$stmt_check = $conn->prepare($sql_check);

if ($stmt_check) {
    $stmt_check->bind_param("ss", $user_email, $user_username);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();

    // Check if the email or username already exists
    if ($result_check->num_rows > 0) {
        $row = $result_check->fetch_assoc();
        
        if ($row['email'] === $user_email) {
            echo json_encode(["success" => false, "errors" => ["email" => "Email is already registered."]]);
        } elseif ($row['username'] === $user_username) {
            echo json_encode(["success" => false, "errors" => ["username" => "Username is already taken."]]);
        }
        
        $stmt_check->close();
        $conn->close();
        exit();
    }

    $stmt_check->close();
} else {
    echo json_encode(["success" => false, "error" => "Database query error."]);
    $conn->close();
    exit();
}

// Hash the password
$hashed_password = password_hash($user_password, PASSWORD_DEFAULT);

// Insert into database
$sql = "INSERT INTO infos (first_name, last_name, username, email, password, birthdate) VALUES (?, ?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql);

if ($stmt) {
    $stmt->bind_param("ssssss", $first_name, $last_name, $user_username, $user_email, $hashed_password, $birthdate);

    if ($stmt->execute()) {
        echo json_encode(["success" => true]);
    } else {
        echo json_encode(["success" => false, "error" => "Failed to register."]);
    }

    $stmt->close();
} else {
    echo json_encode(["success" => false, "error" => "Database query error."]);
}

$conn->close();
?>