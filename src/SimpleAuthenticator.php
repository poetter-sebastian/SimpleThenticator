<?php
declare(strict_types=1);

namespace SebastianDevs;

use Exception;
use ValueError;

/**
 * SimpleAuthenticator is a TOTP based on https://github.com/PHPGangsta/GoogleAuthenticator updated and reworked to php8.2 because of inactivity of the original creator.
 *
 * Should be usable for all TOTP-Apps according to https://datatracker.ietf.org/doc/html/rfc6238
 *
 * @package  sebastian/simplethenticator
 * @author   Sebatian Pötter
 * @version  1.2
 * @access   public
 * @see      https://github.com/poetter-sebastian/SimpleThenticator
 */
class SimpleAuthenticator
{
    private int $codeLength;
    private string $alg;

    /**
     * @param int|null $codeLength Length between 6 and 10
     * @param string|null $usedAlg Used hash algorithm 'SHA1', 'SHA256', 'SHA512'
     * @throws Exception throws ValueError exception if $codeLength is smaller or grater then 10 or if the hash algorithm is not supported
     */
    public function __construct(?int $codeLength = 6, ?string $usedAlg = 'SHA256')
    {
        $this->codeLength = $codeLength ?? 6;
        $this->alg = $usedAlg ?? 'SHA256';

        if (!in_array($this->alg, self::supportedHashAlgorithms(), true)) {
            throw new ValueError('Hash algorithm not allowed. Use one of: ' . implode(', ', self::supportedHashAlgorithms()));
        }

        if($this->codeLength < 6)
        {
            throw new ValueError("Code is less then 6");
        }

        if($this->codeLength > 10)
        {
            throw new ValueError("Code is higher then 10");
        }

        // this should never happen!
        if(!in_array(strtolower($this->alg), hash_hmac_algos(), true))
        {
            // @codeCoverageIgnoreStart
            throw new ValueError("Hash function $this->alg is not supported by hash_hmac");
            // @codeCoverageIgnoreEnd
        }
    }

    /**
     * Gets the current code length
     * @return int
     */
    public function GetCodeLength(): int
    {
        return $this->codeLength;
    }

    /**
     * Gets the set code length
     * @return string returns the current used hash algorithm
     */
    public function getUsedHasAlgorithm(): string
    {
        return $this->alg;
    }

    /**
     * Returns the current used hash algorithm
     * @return string returns the current used hash algorithm
     * @deprecated will be removed in the next version
     */
    public function getAlgorithm(): string
    {
        // @codeCoverageIgnoreStart
        return $this->getUsedHasAlgorithm();
        // @codeCoverageIgnoreEnd
    }

    /**
     * Calculate the code, with a given secret and point in time.
     *
     * @param string $secret
     * @param float|null $timeSlice
     *
     * @return string
     */
    public function getCode(string $secret, ?float $timeSlice = null): string
    {
        $timeSlice = $timeSlice ?? floor(time() / 30);

        $secretKey = self::base32Decode($secret);

        // Pack time into an 8-byte binary string (high 32-bit zero for current-era counters and after 2030 time)
        $time = pack('N2', 0, $timeSlice);
        // Hash it with users' secret key
        $hm = hash_hmac($this->alg, $time, $secretKey, true);
        // Use the last nipple of a result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashPart = substr($hm, $offset, 4);

        // Unpack binary value
        $value = unpack('N', $hashPart)[1] & 0x7FFFFFFF;

        // With codeLength <= 10 this stays within the safe integer range
        $modulo = pow(10, $this->codeLength);

        return str_pad((string)($value % $modulo), $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from Google charts.
     *
     * @param string $label
     * @param string $secret
     * @param string|null $issuer
     * @param array $params width, height and ecc
     *
     * @return string
     *@example getQRCodeGoogleUrl('Example code', '123456789')
     *
     */
    public function getQRCodeGoogleUrl(string $secret, string $label, ?string $issuer = null, array $params = []): string
    {
        $params += [
            'width' => 200,
            'height' => 200,
            'ecc' => 'M',
        ];

        $width = !empty($params['width']) && (int)$params['width'] > 0 ? (int)$params['width'] : 200;
        $height = !empty($params['height']) && (int)$params['height'] > 0 ? (int)$params['height'] : 200;
        $ecc = !empty($params['ecc']) && in_array($params['ecc'], ['L', 'M', 'Q', 'H']) ? $params['ecc'] : 'M';

        $urlencoded = urlencode('otpauth://totp/' .
            (!is_null($issuer) ? $issuer . ':' : '') . $label .
            '?secret=' . $secret .
            ($this->alg != 'SHA1' ? '&algorithm='.$this->alg : '') .
            (!is_null($issuer) ? '&issuer=' . $issuer : ''));

        return "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size={$width}x$height&ecc=$ecc";
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30-second units (8 means 4 minutes before or after)
     * @param int|null $currentTimeSlice time slice if we want to use other that time()
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $currentTimeSlice = null): bool
    {
        $currentTimeSlice = $currentTimeSlice ?? floor(time() / 30);

        if (strlen($code) != $this->codeLength)
        {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i)
        {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if (self::timingSafeEquals($calculatedCode, $code))
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Helper class to decode base32.
     *
     * @param $secret
     * @return string
     */
    protected function base32Decode($secret): string
    {
        if (empty($secret))
        {
            return '';
        }

        $base32chars = $this->getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        foreach (str_split($secret) as $char)
        {
            if (!isset($base32charsFlipped[$char]))
                return '';
        }

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues))
        {
            return '';
        }
        for ($i = 0; $i < 4; ++$i)
        {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i]))
            {
                // @codeCoverageIgnoreStart
                return '';
                // @codeCoverageIgnoreEnd
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8)
        {
            $x = '';
            if (!in_array($secret[$i], $base32chars))
            {
                // @codeCoverageIgnoreStart
                return '';
                // @codeCoverageIgnoreEnd
            }
            for ($j = 0; $j < 8; ++$j)
            {
                $x .= str_pad(base_convert((string)@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); ++$z)
            {
                $binaryString .= (($y = chr((int)base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $secretLength
     *
     * @return string
     * @throws Exception
     */
    public static function createSecret(int $secretLength = 32): string
    {
        $validChars = self::getBase32LookupTable();

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16)
        {
            throw new ValueError('The secret is too short');
        }

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength > 128)
        {
            throw new ValueError('The secret is too long');
        }

        $secret = '';
        $rnd = '';

        if (function_exists('random_bytes'))
        {
            $rnd = random_bytes($secretLength);
        }
        // @codeCoverageIgnoreStart
        elseif (function_exists('openssl_random_pseudo_bytes'))
        {
            $rnd = openssl_random_pseudo_bytes($secretLength, $cryptoStrong);
            if (!$cryptoStrong)
            {
                $rnd = '';
            }
        }
        // @codeCoverageIgnoreEnd
        if (!empty($rnd))
        {
            for ($i = 0; $i < $secretLength; ++$i)
            {
                $secret .= $validChars[ord($rnd[$i]) & 31];
            }
        }
        else
        {
            // @codeCoverageIgnoreStart
            // This should never happen!
            throw new Exception('No source of secure random');
            // @codeCoverageIgnoreEnd
        }

        return $secret;
    }

    /**
     * Get an array with all 32 characters for decoding from/encoding to base32.
     *
     * @return string[]
     */
    public static function getBase32LookupTable(): array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        ];
    }

    /**
     * RFC6238 algorithms only
     * @return string[] Returns the RFC6238 algorithms
     */
    public static function supportedHashAlgorithms(): array
    {
        return ['SHA1', 'SHA256', 'SHA512'];
    }

    /**
     * A timing safe equals comparison
     * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
     *
     * @param string $safeString The internal (safe) value to be checked
     * @param string $userString The user submitted (unsafe) value
     *
     * @return bool True if the two strings are identical
     */
    public static function timingSafeEquals(string $safeString, string $userString): bool
    {
        if (function_exists('hash_equals'))
        {
            return hash_equals($safeString, $userString);
        }
        // @codeCoverageIgnoreStart
        $safeLen = strlen($safeString);
        $userLen = strlen($userString);

        if ($userLen != $safeLen)
        {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; ++$i)
        {
            $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return $result === 0;
        // @codeCoverageIgnoreEnd
    }
}