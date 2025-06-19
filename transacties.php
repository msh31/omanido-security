<?php
session_start();
include 'includes/db.php';

if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header("location: index.php");
    exit;
}

$id = $_GET['id'];

if ($id != $_SESSION['user_id']) {
    header("location: dashboard.php");
    exit;
}

// Gebruikersgegevens ophalen
$stmt = $pdo->prepare("SELECT * FROM user WHERE id = ?");
$stmt->execute([$id]);
$user = $stmt->fetch();

// Uitgaande transacties ophalen
$stmt = $pdo->prepare("SELECT * FROM transaction WHERE sender = ?");
$stmt->execute([$id]);
$outgoingTransactions = $stmt->fetchAll();

// Inkomende transacties ophalen
$stmt = $pdo->prepare("SELECT * FROM transaction WHERE receiver = ?");
$stmt->execute([$id]);
$incomingTransactions = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= $user['username'] ?> | Omanido</title>
    <!-- Voeg Tailwind CSS toe via CDN -->
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.15/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100">
<?php include 'includes/header.php'; ?>

<div class="container mx-auto mt-20 p-6 bg-white shadow-md rounded-md">
    <div class="grid grid-cols-3 gap-4">
        <div class="col-span-1">
            <div class="flex justify-center">
                <img src="img/Omanido1.png" alt="Omanido Logo" class="mb-6 w-1/2">
            </div>
            <h2 class="text-lg text-center font-bold mb-6"><?= $user['username'] ?></h2>
            <p class="text-center mb-6">Saldo: €<?= number_format($user['balance'], 2, ',', '.') ?></p>
            <div class="flex justify-center">
                <a href="dashboard.php"
                   class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">Geld overmaken</a>
            </div>
            <div class="flex justify-center mt-6">
                <a href="logout.php"
                   class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded">Uitloggen</a>
            </div>
        </div>
        <div class="col-span-1">
            <?php if (!empty($outgoingTransactions)): ?>
            <h2 class="text-lg text-center font-bold mb-6">Uitgaande Transacties</h2>
            <div class="bg-red-100 p-2 rounded">
                <?php foreach ($outgoingTransactions as $transaction): ?>
                    <div class="flex justify-between mb-2">
                        <p><?= htmlspecialchars($transaction['description']) ?></p>
                        <p>€<?= number_format($transaction['amount'], 2, ',', '.') ?></p>
                    </div>
                <?php endforeach; ?>
            </div>
            <?php else: ?>
                <p class="text-center text-red-500 font-bold">Er zijn geen uitgaande transacties.</p>
            <?php endif; ?>
        </div>

        <div class="col-span-1">
            <?php if (!empty($incomingTransactions)): ?>
                <h2 class="text-lg text-center font-bold mb-6">Inkomende Transacties</h2>
                <div class="bg-green-100 p-2 rounded">
                    <?php foreach ($incomingTransactions as $transaction): ?>
                        <div class="flex justify-between mb-2">
                            <p><?= htmlspecialchars($transaction['description']) ?></p>
                            <p>€<?= number_format($transaction['amount'], 2, ',', '.') ?></p>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <p class="text-center text-red-500 font-bold">Er zijn geen inkomende transacties.</p>
            <?php endif; ?>
        </div>
    </div>
</div>


</body>
</html>
