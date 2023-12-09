<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use src\SimpleAuthenticator;

class SimpleAuthenticatorTest extends TestCase
{
    /**
     * @return array[] of parameters
     * Thanks to https://github.com/PHPGangsta/GoogleAuthenticator/pull/41
     */
    public static function paramsProvider(): array
    {
        return [
            [null, null, null, '200x200', 'M'],
            [-1, -1, null, '200x200', 'M'],
            [250, 250, 'L', '250x250', 'L'],
            [250, 250, 'M', '250x250', 'M'],
            [250, 250, 'Q', '250x250', 'Q'],
            [250, 250, 'H', '250x250', 'H'],
            [250, 250, 'Z', '250x250', 'M'],
        ];
    }

    /**
     * @return array[] of check triples
     */
    public static function codeProvider(): array
    {
        // Secret, unix-time, code
        return [
            ['SECRET', 0, '377331'],
            ['SECRET', 1385909245, '010454'],
            ['SECRET', 1378934578, '299040'],
        ];
    }

    public function testGenerator()
    {
        $auth = new SimpleAuthenticator();
        try
        {
            $secret = $auth->createSecret();
        }
        catch (Exception $e)
        {
            echo $e->getMessage();
            exit();
        }
        echo "Secret is: ".$secret."\n\n";

        $qrCodeUrl = $auth->getQRCodeGoogleUrl($secret, 'Testo@test.test', 'Vintage Story');
        echo "Google Charts URL for the QR-Code: ".$qrCodeUrl."\n\n";

        $oneCode = $auth->getCode($secret);
        echo "Checking Code '$oneCode' and Secret '$secret':\n";

        $this->assertTrue($auth->verifyCode($secret, $oneCode, 2));
    }

    public function testCreateSecretTooLowSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(0);
    }

    public function testCreateSecretTooHighSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(99999);
    }

    public function testCreateSecretOnNull()
    {
        $auth = new SimpleAuthenticator(null);
        $this->assertEquals(6, $auth->getCodeLength());
        $this->assertEquals('SHA256', $auth->getAlgorithm());

        $auth = new SimpleAuthenticator(6, null);
        $this->assertEquals(6, $auth->getCodeLength());
        $this->assertEquals('SHA256', $auth->getAlgorithm());
    }


    public function testCreateSecretWithWrongHashFunction()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(6, 'DOGGO');
    }

    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret();

        $this->assertEquals(32, strlen($secret));
    }

    public function testCreateSecretLengthCanBeSpecified()
    {
        $auth = new SimpleAuthenticator();

        for ($secretLength = 16; $secretLength < 100; ++$secretLength)
        {
            $secret = $auth->createSecret($secretLength);

            $this->assertEquals(strlen($secret), $secretLength);
        }
    }

    /**
     * @dataProvider codeProvider
     */
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code)
    {
        $auth = new SimpleAuthenticator();

        $this->assertEquals($code, $auth->getCode($secret, $timeSlice));
    }

    public function testGetQRCodeGoogleUrlReturnsCorrectUrl()
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $name = 'Test';
        $url = $auth->getQRCodeGoogleUrl($secret, $name);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals('https', $urlParts['scheme']);
        $this->assertEquals('api.qrserver.com', $urlParts['host']);
        $this->assertEquals('/v1/create-qr-code/', $urlParts['path']);

        $expectedChl = 'otpauth://totp/' . $name . '?secret=' . $secret . '&algorithm=SHA256';

        $this->assertEquals($queryStringArray['data'], $expectedChl);
    }

    public function testVerifyCode()
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);

        $this->assertTrue($result);

        $code = 'INVALIDCODE';
        $result = $auth->verifyCode($secret, $code);

        $this->assertFalse($result);
    }

    public function testVerifyCodeWithLeadingZero()
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);
        $this->assertTrue($result);

        $code = '0'.$code;
        $result = $auth->verifyCode($secret, $code);
        $this->assertFalse($result);
    }

    /**
     * @dataProvider paramsProvider
     * Thanks to https://github.com/PHPGangsta/GoogleAuthenticator/pull/41
     */
    public function testGetQRCodeGoogleUrlReturnsCorrectUrlWithOptionalParameters($width, $height, $level, $expectedSize, $expectedLevel)
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $name = 'Test';
        $url = $auth->getQRCodeGoogleUrl($secret, $name, null, [
            'width' => $width,
            'height' => $height,
            'ecc' => $level
        ]);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertEquals($queryStringArray['size'], $expectedSize);
        $this->assertEquals($queryStringArray['ecc'], $expectedLevel);
    }
}
