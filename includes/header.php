<?php
// Controleer of de gebruiker is ingelogd
if (isset($_SESSION['loggedin'])) {
    $username = $_SESSION['username'];
    $userId = $_SESSION['user_id'];
}
?>

<div class="bg-white py-4 shadow-md">
    <div class="max-w-7xl mx-auto px-4 flex justify-between items-center">
        <a href="<?= isset($_SESSION['loggedin']) ? 'dashboard.php' : 'index.php' ?>">
            <img src="../img/Omanido2.png" alt="Bank Logo" class="h-12">
        </a>
        <?php if (isset($_SESSION['loggedin'])): ?>
            <div class="text-right">
                <p class="text-gray-500 text-sm">Welkom,  <a href="transacties.php?id=<?= $userId ?>" class="text-blue-600 hover:underline"><?= $username ?></a></p>
               
            </div>
        <?php endif; ?>
    </div>
</div>
