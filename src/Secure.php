<?php
namespace Resonantcore\Lib;

abstract class Secure
{

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
        $rem = (PHP_INT_MAX - $range + 1) % $range;
        do {
            $val = self::random_positive_int();
        } while ($val > $rem);
        return (int) ($min + $val % $range);
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
