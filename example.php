<?php

// kafene\Csrf Example:

session_start();

$csrf = new \kafene\Csrf();
$csrf->setRequestParam('custom_csrf_token_param');

try {
    $csrf->protect();
    $result = "CSRF check passed or no data sent";
} catch (\kafene\CsrfException $e) {
    $result = $e->getMessage() . ' - Form ignored.';
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CSRF Protection Demo</title>
    <style>
        #result {
            color: #f22;
            font-weight: bold;
        }
    </style>
<body>

    <h1>CSRF Protection Demo</h1>
    <pre id="result">
        <?= $result ?>
    </pre>

    <form name="csrf_form" action="#" method="post">
        <h2>Form using generated token.</h2>
        <?= $csrf->formInput() ?>
        <input type="text" name="field" value="somevalue">
        <input type="submit" value="Send form">
    </form>

    <form name="nocsrf_form" action="#" method="post">
        <h2>Form simulating a CSRF attack.</h2>
        <input type="hidden" name="custom_csrf_token_param" value="whateverkey">
        <input type="text" name="field" value="somevalue">
        <input type="submit" value="Send form">
    </form>
</body>
</html>
