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
            ['SNEFRU'],
            ['SNEFRU256'],
            ['GOST'],
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

        $this->assertTrue($auth->getUsedHasAlgorithm() === 'SHA256');
        $this->assertTrue($auth->verifyCode($secret, $oneCode, 2));
    }

    /**
     * Tests if code length is too low
     * @throws Exception
     */
    public function testConstructorException()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(0);
        $secret = $auth->createSecret(0);
    }

    /**
     * Tests if secret is too low
     * @throws Exception
     */
    public function testCreateSecretTooLowSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(0);
    }

    /**
     * Tests if secret is too high
     * @throws Exception
     */
    public function testCreateSecretTooHighSecret()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(99999);
    }

    /**
     * Test maximum code length validation
     * @throws Exception
     */
    public function testMaximumCodeLengthValidation(): void
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(11);
    }

    /**
     * Test code generation with maximum length
     * @throws Exception
     */
    public function testCodeGenerationWithMaximumLength(): void
    {
        $auth = new SimpleAuthenticator(10); // Maximum allowed length
        $secret = $auth->createSecret();
        $code = $auth->getCode($secret);
        $this->assertEquals(10, strlen($code));
    }

    /**
     * Test very long secret generation
     */
    public function testVeryLongSecretGeneration(): void
    {
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret(128); // Maximum allowed secret length
        $this->assertEquals(128, strlen($secret));
    }


    /**
     * Test boundary conditions for time slices
     */
    public function testTimeSliceBoundaryConditions(): void
    {
        $auth = new SimpleAuthenticator();
        $secret = 'SECRET';

        // Test with a valid time slice
        $code = $auth->getCode($secret, 0);
        $this->assertIsString($code);
        $this->assertGreaterThanOrEqual(0, strlen($code));

        // Test with a negative time slice
        $code = $auth->getCode($secret, -100);
        $this->assertIsString($code);
    }


    /**
     * Test invalid time slice in getCode
     */
    public function testGetCodeWithInvalidTimeSlice(): void
    {
        $auth = new SimpleAuthenticator();
        $secret = 'SECRET';

        // Test with a very large time slice
        $code = $auth->getCode($secret, PHP_INT_MAX);
        $this->assertIsString($code);
        $this->assertGreaterThanOrEqual(0, strlen($code));
    }

    /**
     * Test null behavior
     * @throws Exception
     */
    public function testCreateSecretOnNull()
    {
        $auth = new SimpleAuthenticator(null);
        $this->assertEquals(6, $auth->GetCodeLength());
        $this->assertEquals('SHA256', $auth->getUsedHasAlgorithm());

        $auth = new SimpleAuthenticator(6, null);
        $this->assertEquals(6, $auth->GetCodeLength());
        $this->assertEquals('SHA256', $auth->getUsedHasAlgorithm());
    }

    /**
     * Test edge case for timing safe equals with maximum string length
     */
    public function testTimingSafeEqualsWithMaximumStringLength(): void
    {
        $longString = str_repeat('A', 1000);
        $this->assertTrue(SimpleAuthenticator::timingSafeEquals($longString, $longString));
        $differentString = str_repeat('B', 1000);
        $this->assertFalse(SimpleAuthenticator::timingSafeEquals($longString, $differentString));
    }

    /**
     * Test only usable hash algorithm
     * @throws Exception
     */
    #[DataProvider('hashAlgorithmProvider')]
    public function testSupportedHashAlgorithm(string $algorithm)
    {
        if (!in_array($algorithm, SimpleAuthenticator::supportedHashAlgorithms(), true)) {
            $this->expectException(ValueError::class);
            $auth = new SimpleAuthenticator(6, $algorithm);
        }

        $auth = new SimpleAuthenticator(6, $algorithm);

        $this->assertEquals($algorithm, $auth->getUsedHasAlgorithm());

        $secret = 'SECRET';
        $code = $auth->getCode($secret);
        $result = $auth->verifyCode($secret, $code);

        $this->assertTrue($result);
    }

    /**
     * Test specific not existing hash algorithm
     * @throws Exception
     */
    public function testCreateSecretWithWrongHashFunction()
    {
        $this->expectException(ValueError::class);
        $auth = new SimpleAuthenticator(6, 'DOGGO');
    }

    /**
     * Test default secret creation
     * @throws Exception
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $auth = new SimpleAuthenticator();
        $secret = $auth->createSecret();

        $this->assertEquals(32, strlen($secret));
    }

    /**
     * Test specified secret length
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

    /**
     * Test specified secret, time, and code combinations
     */
    #[DataProvider('codeProvider')]
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code)
    {
        $auth = new SimpleAuthenticator();

        $this->assertEquals($code, $auth->getCode($secret, $timeSlice));
    }

    /**
     * Test URL generation behavior
     */
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

    /**
     * Test default code verification
     */
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

    /**
     * Test verification with a leading zero
     */
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
     * Test wrong code check
     */
    public function testVerifyCodeWithWrongCode()
    {
        $auth = new SimpleAuthenticator();

        $secret = 'SECRET';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    /**
     * Test empty check
     */
    public function testEmptySecret()
    {
        $auth = new SimpleAuthenticator();

        $secret = '';
        $code = "000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    /**
     * Test too long code check
     */
    public function testLongerUserKey()
    {
        $auth = new SimpleAuthenticator();

        $secret = '';
        $code = "00000000";
        $result = $auth->verifyCode($auth->getCode($secret), $code);
        $this->assertFalse($result);
    }

    /**
     * Test optional parameters
     * Thanks to https://github.com/PHPGangsta/GoogleAuthenticator/pull/41
     */
    #[DataProvider('paramsProvider')]
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
     * Test base-32 decoder
     * @throws ReflectionException
     */
    public function testBase32DecodeWithValidSecret(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP'; // Example valid base32 secret
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertNotEmpty($decoded);
    }

    /**
     * Test base-32 decoder on empty input
     * @throws ReflectionException
     */
    public function testBase32DecodeWithEmptySecret(): void
    {
        $secret = '';
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * Test base-32 decoder with invalide characters
     * @throws ReflectionException
     */
    public function testBase32DecodeWithInvalidCharacters(): void
    {
        $secret = 'INVALIDBASE32?!';
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * Test base-32 decoder with wrong padding
     * @throws ReflectionException
     */
    public function testBase32DecodeWithInvalidPaddingCount(): void
    {
        $secret = 'JBSWY3DPEHPK3PXP=='; // Invalid padding
        $decoded = $this->invokeBase32Decode($secret);
        $this->assertSame('', $decoded);
    }

    /**
     * Test base-32 decoder with correct padding
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
     * Test base-32 decoder invocation
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
