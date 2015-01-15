<?php
namespace Resonantcore\Lib;

abstract class Secure
{

    /**
     * Prevent timing attack
     *
     * @param  string $knownString
     * @param  string $userString
     * @return bool
     */
    public static function hash_equals($knownString, $userString)
    {
        if (function_exists('\hash_equals')) {
            return \hash_equals($knownString, $userString);
        }
        if (strlen($knownString) !== strlen($userString)) {
            return false;
        }
        $len = strlen($knownString);
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
    }

    /**
     * Generate a random number between $min and $max
     * using a CSPRNG
     *
     * @param int $min Minimum value
     * @param int $max Maximum value
     * @return int
     */
    public static function random($min, $max)
    {
        $range = $max - $min;
        if ($range < 2) {
            return $min;
        }

        // 7776 -> 13
        $bits = ceil(log($range)/log(2));

        // 2^13 - 1 == 8191 or 0x00001111 11111111
        $mask =  ceil(pow(2, $bits)) - 1;
        do {
            // Grab a random integer
            $val = self::random_positive_int();
            if ($val === FALSE) {
                // RNG failure
                return FALSE;
            }
            // Apply mask
            $val = $val & $mask;

            // If $val is larger than the maximum acceptable number for
            // $min and $max, we discard and try again.

        } while ($val > $range);

        return (int) ($min + $val);
    }

    /**
     * Generate a cryptographically secure pseudorandom number
     * @param integer $bytes - Number of bytes needed
     * @param bool $fail_open - Trigger a warning rather than throwing an exception
     * @return string
     */
    public static function random_bytes($bytes, $fail_open = false)
    {
        if (!is_int($bytes) || $bytes < 1) {
            if ($fail_open) {
                \trigger_error("\$bytes must be a positive integer greater than zero.", E_USER_WARNING);
                return false;
            }
            throw new \Exception("\$bytes must be a positive integer greater than zero.");
        }
        if (function_exists('\mcrypt_create_iv')) {
            // mcrypt_create_iv() is smart; uses Windows APIs to get entropy if it needs to
            return \mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
        } elseif (\is_readable('/dev/urandom')) {
            // If /dev/urandom is readable, grab some entropy
            $fp = \fopen('/dev/urandom', 'rb');
            $buf = \fread($fp, $bytes);
            \fclose($fp);
            if ($buf !== false) {
                return $buf;
            }
        }

        // OpenSSL is really a last resort for us...
        return \openssl_random_pseudo_bytes($bytes);
    }

    /**
     * Wrapper for htmlentities()
     *
     * @param string $untrusted
     * @return string
     */
    public static function noHTML($untrusted)
    {
        return \htmlentities($untrusted, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * Is the given filename safe for use in file operations?
     * @param string $file_name (UNTRUSTED)
     * @param string $jail_dir (DEVELOPER SUPPLIED)
     * @return string | false
     */
    public static function file_valid($file, $jail_dir = null)
    {
        if (empty($jail_dir)) {
            $jail_dir = \realpath($_SERVER['DOCUMENT_ROOT']);
        }
        $dir = \dirname($file);
        do {
            if ($dir === \dirname($dir)) {
                //var_dump([$dir, \dirname($dir)]);
                return false;
            }
            $dir = \dirname($dir);
            if (!\is_dir($dir)) {
                echo $dir;
                return false;
            }

            if (\strpos(\realpath($dir), $jail_dir) === 0) {
                return true;
            }
        } while ($dir);
        return false;
    }

    /**
     * Returns a random positive integer
     * @return int
     */
    public static function random_positive_int() {
        $buf = self::random_bytes(PHP_INT_SIZE);

        $val = 0;
        $i = strlen($buf);

        do {
            $i--;
            $val <<= 8;
            $val |= ord($buf[$i]);
        } while ($i != 0);

        return $val & PHP_INT_MAX;
    }

}
