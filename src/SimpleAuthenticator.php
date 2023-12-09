<?php
declare(strict_types=1);

namespace src;

use Random\RandomException;
use Exception;
use ValueError;

/**
 * SimpleAuthenticator is a TOTP based on https://github.com/PHPGangsta/GoogleAuthenticator updated and reworked to php8.2 because of inactivity of the original creator.
 *
 * Should be usable for all TOTP-Apps according to https://datatracker.ietf.org/doc/html/rfc6238
 *
 * @package  sebastian/simplethenticator
 * @author   Sebatian Pötter
 * @version  1.0
 * @access   public
 * @see      https://github.com/poetter-sebastian/SimpleThenticator
 */
class SimpleAuthenticator
{
    private int $codeLength;
    private string $alg;

    /**
     * @param int|null $codeLength
     * @param string|null $usedAlg
     * @throws Exception
     */
    public function __construct(?int $codeLength = 6, ?string $usedAlg = 'SHA256')
    {
        $this->codeLength = $codeLength ?? 6;
        $this->alg = $usedAlg ?? 'SHA256';

        if($this->codeLength < 6)
        {
            throw new Exception("Code is less then 6");
        }

        if(!in_array(strtolower($this->alg), hash_hmac_algos()))
        {
            throw new ValueError("Hash function is not supported by hash_hmac");
        }
    }

    /**
     * Gets the used algorithm
     * @return int
     */
    public function getCodeLength(): int
    {
        return $this->codeLength;
    }

    /**
     * Gets the set code length
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->alg;
    }

    /**
     * Calculate the code, with given secret and point in time.
     *
     * @param string $secret
     * @param float|null $timeSlice
     *
     * @return string
     */
    public function getCode(string $secret, float $timeSlice = null): string
    {
        $timeSlice = $timeSlice ?? floor(time() / 30);

        $secretKey = self::base32Decode($secret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac($this->alg, $time, $secretKey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashPart = substr($hm, $offset, 4);

        // Unpack binary value
        $value = unpack('N', $hashPart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

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

        return "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size={$width}x{$height}&ecc=$ecc";
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $currentTimeSlice time slice if we want to use other that time()
     *
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, int $currentTimeSlice = null): bool
    {
        if ($currentTimeSlice === null)
        {
            $currentTimeSlice = floor(time() / 30);
        }

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
     *
     * @return bool|string
     */
    protected function base32Decode($secret): bool|string
    {
        if (empty($secret))
        {
            return '';
        }

        $base32chars = $this->getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues))
        {
            return false;
        }
        for ($i = 0; $i < 4; ++$i)
        {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i]))
            {
                return false;
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
                return false;
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
     * @throws RandomException
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
        elseif (function_exists('openssl_random_pseudo_bytes'))
        {
            $rnd = openssl_random_pseudo_bytes($secretLength, $cryptoStrong);
            if (!$cryptoStrong)
            {
                $rnd = '';
            }
        }
        if (!empty($rnd))
        {
            for ($i = 0; $i < $secretLength; ++$i)
            {
                $secret .= $validChars[ord($rnd[$i]) & 31];
            }
        }
        else
        {
            throw new Exception('No source of secure random');
        }

        return $secret;
    }

    /**
     * Get array with all 32 characters for decoding from/encoding to base32.
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
    }
}