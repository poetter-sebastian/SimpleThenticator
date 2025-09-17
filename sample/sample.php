<?php

require_once('../src/SimpleAuthenticator.php');

use SebastianDevs\SimpleAuthenticator;

try {
    $auth = new SimpleAuthenticator(6, 'SHA1');
    try
    {
        $secret = $auth->createSecret();
    }
    catch (Exception $e)
    {
        echo $e->getMessage();
        exit();
    }
    echo 'Secret is: ' . $secret . '\n';

    $qrCodeUrl = $auth->getQRCodeGoogleUrl($secret, 'Testo@test.test', 'Business');
    echo 'QR-Code: ' . $qrCodeUrl . '\n';

    $oneCode = $auth->getCode($secret);
    echo 'Checking Code ' . $oneCode . ' and Secret ' . $secret . ':\n';

    echo $auth->verifyCode($secret, $oneCode, 2)? 'OK': 'NOT OK';
} catch (Exception $e) {
    echo 'Error while generating secret: ' . $e->getMessage();
}
