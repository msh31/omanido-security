<?php
function sanitizeString($input, $maxLength = null) {
    $input = trim($input);
    $input = stripslashes($input);
    
    if ($maxLength !== null && strlen($input) > $maxLength) {
        return false;
    }
    
    return $input;
}

function sanitizeUsername($username) {
    $username = sanitizeString($username, 50);
    
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
        return false;
    }
    
    return $username;
}

function sanitizeAmount($amount) {
    $amount = preg_replace('/[^0-9.]/', '', $amount);
    
    $amount = floatval($amount);

    if ($amount <= 0 || $amount > PHP_FLOAT_MAX) {
        return false;
    }
    
    // Round to 2 decimal places
    return round($amount, 2);
}

function sanitizeDescription($description) {
    $description = sanitizeString($description, 500);
    
    if (!preg_match('/^[a-zA-Z0-9\s.,!?-]+$/', $description)) {
        return false;
    }
    
    return $description;
}

function validatePassword($password) {
    if (strlen($password) < 12) {
        return "Wachtwoord moet minimaal 12 tekens lang zijn.";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return "Wachtwoord moet minimaal één hoofdletter bevatten.";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return "Wachtwoord moet minimaal één kleine letter bevatten.";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return "Wachtwoord moet minimaal één cijfer bevatten.";
    }
    
    return true;
}