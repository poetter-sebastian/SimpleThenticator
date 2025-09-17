<?php
declare(strict_types=1);

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SebastianDevs\SimpleAuthenticator;

#[CoversClass(SimpleAuthenticator::class)]
final class SimpleAuthenticatorTest extends TestCase
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

    /**
     * @return array[] of hash algorithm names
     */
    public static function hashAlgorithmProvider(): array
    {
        return [
            ['MD5'],
            ['SHA1'],
            ['SHA224'],
            ['SHA256'],
            ['SHA384'],
            ['SHA512'],
            ['SHA512/224'],
            ['SHA512/256'],
            ['SHA3-224'],
            ['SHA3-256'],
            ['SHA3-384'],
            ['SHA3-512'],
            ['RIPEMD160'],
            ['WHIRLPOOL'],
            ['TIGER128,3'],
            ['TIGER160,3'],
            ['TIGER192,3'],
            ['TIGER128,4'],
            ['TIGER160,4'],
            ['TIGER192,4'],
            ['SNEFRU'],
            ['SNEFRU256'],
            ['GOST'],
            ['HAVAL128,3'],
            ['HAVAL160,3'],
            ['HAVAL192,3'],
            ['HAVAL224,3'],
            ['HAVAL256,3'],
            ['HAVAL128,4'],
            ['HAVAL160,4'],
            ['HAVAL192,4'],
            ['HAVAL224,4'],
            ['HAVAL256,4'],
            ['HAVAL128,5'],
            ['HAVAL160,5'],
            ['HAVAL192,5'],
            ['HAVAL224,5'],
            ['HAVAL256,5'],
        ];
    }

    public function testGenerator()
    {
        ob_start();
        $auth = new SimpleAuthenticator();
        try
        {
            $secret = $auth->createSecret();
        }
        catch (Exception $e)
        {
            echo $e->getMessage();
            $this->fail();
        }
        echo "Secret is: ".$secret."\n\n";

        $qrCodeUrl = $auth->getQRCodeGoogleUrl($secret, 'Testo@test.test', 'Company');
        echo "Google Charts URL for the QR-Code: ".$qrCodeUrl."\n\n";

        $oneCode = $auth->getCode($secret);
        echo "Checking Code '$oneCode' and Secret '$secret':\n";

        ob_end_clean();

        $this->assertTrue($auth->GetUsedHasAlgorithm() === 'SHA256');
        $this->assertTrue($auth->verifyCode($secret, $oneCode, 2));
    }

    /**
     * @throws Exception
     */
    public function testConstructorException()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(0);
        $secret = $auth->createSecret(0);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretTooLowSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(0);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretTooHighSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(99999);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretOnNull()
    {
        $auth = new SimpleAuthenticator(null);
        $this->assertEquals(6, $auth->GetCodeLength());
        $this->assertEquals('SHA256', $auth->getAlgorithm());

        $auth = new SimpleAuthenticator(6, null);
        $this->assertEquals(6, $auth->GetCodeLength());
        $this->assertEquals('SHA256', $auth->getAlgorithm());
    }

    /**
     * @throws Exception
     */
    #[DataProvider('hashAlgorithmProvider')]
    public function testSupportedHashAlgorithm(string $algorithm)
    {
        $auth = new SimpleAuthenticator(6, $algorithm);
        $this->assertEquals($algorithm, $auth->GetUsedHasAlgorithm());

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);

        $this->assertTrue($result);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretWithWrongHashFunction()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(6, 'DOGGO');
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret();

        $this->assertEquals(32, strlen($secret));
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretLengthCanBeSpecified()
    {
        $auth = new SimpleAuthenticator();

        for ($secretLength = 16; $secretLength < 100; ++$secretLength)
        {
            $secret = $auth->createSecret($secretLength);

            $this->assertEquals(strlen($secret), $secretLength);
        }
    }

    #[DataProvider('codeProvider')] #[DataProvider('codeProvider')]
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

    public function testVerifyCodeWithWrongCode()
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    public function testEmptySecret()
    {
        $auth = new SimpleAuthenticator();

        $secret = '';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    public function testLongerUserKey()
    {
        $auth = new SimpleAuthenticator();

        $secret = '';
        $code = "00000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    /**
     * Thanks to https://github.com/PHPGangsta/GoogleAuthenticator/pull/41
     */
    #[DataProvider('paramsProvider')] #[DataProvider('paramsProvider')]
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

    /**
     * @throws ReflectionException
     */
    public function testBase32DecodeWithValidSecret(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP'; // Example valid base32 secret
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertNotEmpty($decoded);
    }

    /**
     * @throws ReflectionException
     */
    public function testBase32DecodeWithEmptySecret(): void
    {
        $secret = '';
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * @throws ReflectionException
     */
    public function testBase32DecodeWithInvalidCharacters(): void
    {
        $secret = 'INVALIDBASE32?!';
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * @throws ReflectionException
     */
    public function testBase32DecodeWithInvalidPaddingCount(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP=='; // Invalid padding
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * @throws ReflectionException
     */
    public function testBase32DecodeWithPaddingCharacters(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP='; // Valid base32 secret with padding
        $decoded = $this->invokeBase32Decode($secret);

        // Check that the padding character is removed and the decoding is correct
        $this->assertNotEmpty($decoded);
        $this->assertIsString($decoded);

        // Check the length of the decoded string
        $this->assertEquals(10, strlen($decoded)); // Expected length based on the valid base32 secret
    }

    /**
     * Test timingSafeEquals with identical strings
     */
    public function testTimingSafeEqualsIdenticalStrings()
    {
        $string1 = "testString";
        $string2 = "testString";
        $this->assertTrue(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with different strings of the same length
     */
    public function testTimingSafeEqualsDifferentStringsSameLength()
    {
        $string1 = "testString";
        $string2 = "testStrung"; // One character different
        $this->assertFalse(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with different strings of different lengths
     */
    public function testTimingSafeEqualsDifferentLengths()
    {
        $string1 = "testString";
        $string2 = "testStr"; // Shorter length
        $this->assertFalse(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with empty strings
     */
    public function testTimingSafeEqualsEmptyStrings()
    {
        $string1 = "";
        $string2 = "";
        $this->assertTrue(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with one empty string
     */
    public function testTimingSafeEqualsOneEmptyString()
    {
        $string1 = "testString";
        $string2 = "";
        $this->assertFalse(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with special characters
     */
    public function testTimingSafeEqualsSpecialCharacters()
    {
        $string1 = "test@String!";
        $string2 = "test@String!";
        $this->assertTrue(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with strings containing numeric characters
     */
    public function testTimingSafeEqualsNumericCharacters()
    {
        $string1 = "1234567890";
        $string2 = "1234567890";
        $this->assertTrue(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * Test timingSafeEquals with strings that have different casing
     */
    public function testTimingSafeEqualsDifferentCasing()
    {
        $string1 = "TestString";
        $string2 = "teststring"; // Different casing
        $this->assertFalse(SimpleAuthenticator::timingSafeEquals($string1, $string2));
    }

    /**
     * @throws ReflectionException
     */
    private function invokeBase32Decode(string $secret): string
    {
        $authenticator = new SimpleAuthenticator();
        $reflection = new ReflectionClass($authenticator);
        $method = $reflection->getMethod('base32Decode');
        return $method->invoke($authenticator, $secret);
    }
}
