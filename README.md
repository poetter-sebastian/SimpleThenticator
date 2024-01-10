# SimpleThenticator

* Copyright (c) 2023, [https://poetter-sebastian.github.io](https://poetter-sebastian.github.io/)
* Author: Sebastian Pötter, ([@PHPGangsta](https://github.com/PHPGangsta/GoogleAuthenticator), [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)) and [contributors](https://github.com/poetter-sebastian/SimpleThenticator/graphs/contributors)
* Licensed under the [BSD 2-Clause "Simplified" License](https://github.com/poetter-sebastian/SimpleThenticator/blob/main/LICENSE).

<p align="center">
    <a href="LICENSE" target="_blank">
        <img alt="Software License" src="https://img.shields.io/badge/lisence-BSD_2_Clause-green?style=flat-square">
    </a>
    <a href="https://packagist.org/packages/sebastiandevs/simplethenticator" target="_blank">
        <img alt="Total Downloads" src="https://img.shields.io/packagist/dt/sebastiandevs/simplethenticator.svg?style=flat-square">
    </a>
    <a href="https://packagist.org/packages/sebastiandevs/simplethenticator" target="_blank">
        <img alt="Latest Stable Version" src="https://img.shields.io/packagist/v/sebastiandevs/simplethenticator.svg?style=flat-square&label=stable">
    </a>
</p>

This class can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret. It implements TOTP
according to [RFC6238](https://tools.ietf.org/html/rfc6238)

Example:
------

Look at the function [TestGenerator()](https://github.com/poetter-sebastian/SimpleThenticator/blob/main/tests/SimpleAuthenticatorTest.php) in [tests](https://github.com/poetter-sebastian/SimpleThenticator/tree/main/tests)

(Other hash functions other than SHA1 only works for Google-Authenticator at the moment!)
```php
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
echo "Secret is: ".$secret."\n";

$qrCodeUrl = $auth->getQRCodeGoogleUrl($secret, 'Testo@test.test', 'Business');
echo "QR-Code: ".$qrCodeUrl."\n";

$oneCode = $auth->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

echo $auth->verifyCode($secret, $oneCode, 2)? 'OK': 'NOT OK';

```
output:
```
Secret is: S4VWK6CWPA3PMU2HZM2YEDZGSF2DQL3V

Google Charts URL for the QR-Code: https://api.qrserver.com/v1/create-qr-code/?data=otpauth%3A%2F%2Ftotp%2FVintage+Story%3ATesto%40test.test%3Fsecret%3DS4VWK6CWPA3PMU2HZM2YEDZGSF2DQL3V%26algorithm%3DSHA256%26issuer%3DVintage+Story&size=200x200&ecc=M

Checking Code '439195' and Secret 'S4VWK6CWPA3PMU2HZM2YEDZGSF2DQL3V':
OK
```

Installation:
-------------
### [Composer](https://getcomposer.org/doc/01-basic-usage.md)

- To use this package perform the following command:

```composer require sebastiandevs/simplethenticator```

### Simple usage

- To use the class just import the [SimpleAuthenticator.php](https://github.com/poetter-sebastian/SimpleThenticator/blob/main/src/SimpleAuthenticator.php) as ```require_once()``` in your PHP code

Run Tests:
----------

- All tests are inside [tests](https://github.com/poetter-sebastian/SimpleThenticator/tree/main/tests) folder.
- Execute `composer run-script build-dev` to install all dependencies
- Execute `composer run-script test` to run all tests in the test folder

Better library:
----------
- For better code or complex implementations: please use [RobThree/TwoFactorAuth](https://github.com/RobThree/TwoFactorAuth)!
