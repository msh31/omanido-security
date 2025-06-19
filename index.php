<?php 
// error_reporting(E_ALL);
// ini_set('display_errors', 1);
//

// session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.gc_maxlifetime', 300); // 5 minutes

session_start();
include 'includes/db.php';
include 'includes/csrf.php';
include 'includes/sanitize.php';

//Tables aanmaken
include 'includes/userTable.php';
include 'includes/transactionTable.php';

//Controleer of post is geset
if($_SERVER["REQUEST_METHOD"] == "POST") {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = "Ongeldig verzoek. Probeer opnieuw.";
    } else {
        // Gebruikersnaam en wachtwoord uit post halen
        $username = sanitizeUsername($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if ($username === false) {
            $error = "Ongeldige gebruikersnaam.";
        } elseif (empty($username) || empty($password)) {
            $error = "Vul alle velden in.";
        } else {
            $sql = "SELECT id, username, password FROM user WHERE username = :username";
            $stmt = $pdo->prepare($sql);

            $stmt->bindParam(':username', $username);

            $stmt->execute();
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user && password_verify($password, $user['password'])) {
                session_regenerate_id(true);

                $_SESSION['loggedin'] = true;
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];

                header("location: dashboard.php");
                exit();
            } else {
                $error = "Gebruikersnaam of wachtwoord is onjuist";
            }
        }
    }
}

?>

<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omanido</title>
    <!-- Voeg Tailwind CSS toe via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
    <?php include 'includes/header.php'; ?>

    <div class="container mx-auto mt-20 p-6 bg-white max-w-sm shadow-md rounded-md">
        <div class="flex justify-center">
            <img src="img/Omanido1.png" alt="Omanido Logo" class="mb-6 w-1/2"> <!-- Aanpassen van de breedte naar 1/2 van de container -->
        </div>
        <h2 class="text-lg text-center font-bold mb-6">Inloggen bij Omanido</h2>

        <?php if(isset($error)): ?>
            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                <strong class="font-bold">Fout!</strong>
                <span class="block sm:inline"><?= htmlspecialchars($error) ?></span>
            </div>
        <?php endif; ?>

        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
            <?= getCSRFField() ?>

            <div class="mb-4">
                <label for="username" class="block text-sm font-medium text-gray-700">Gebruikersnaam:</label>
                <input type="text" id="username" name="username" class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
            </div>
            <div class="mb-6">
                <label for="password" class="block text-sm font-medium text-gray-700">Wachtwoord:</label>
                <input type="password" id="password" name="password" class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500">
            </div>
            <input type="submit" value="Inloggen" class="w-full bg-blue-600 text-white font-bold py-2 px-4 rounded hover:bg-blue-700 focus:outline-none focus:shadow-outline">
        </form>
        <a href="register.php" class="block text-center text-sm text-blue-600 hover:underline mt-4">Nog geen account? Registreer hier</a>
    </div>

    <div class="mt-4 p-2 border border-gray-300 rounded">
        <label class="block text-sm font-medium text-gray-700">Uitgevoerde SQL-query:</label>
        <textarea readonly class="mt-1 block w-full border rounded-md py-2 px-3 resize-none" rows="4">
            <?php 
                if(isset($sql)) {
                    echo $sql;
                } else {
                    echo "Log in om je SQL query te zien";
                }
            ?>
        </textarea>
    </div>

    
</body>
</html>
