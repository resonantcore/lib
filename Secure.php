<?php

namespace Resonantcore\Lib;

abstract class Secure
{
    /**
     * Generate a cryptographically secure pseudorandom number
     * @param integer $bytes - Number of bytes needed
     * @param bool $fail_open - Trigger a warning rather than throwing an exception
     * @return string
     */
    public function random($bytes, $fail_open = false)
    {
        if (!is_int($bytes) || $bytes < 1) {
            if ($fail_open) {
                \trigger_error(
                    "\$bytes must be a positive integer greater than zero.",
                    E_USER_WARNING
                );
                return false;
            }
            throw new \Exception("\$bytes must be a positive integer greater than zero.");
        }
        if (function_exists('\mcrypt_create_iv')) {
            return \mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
        }
        return \openssl_random_pseudo_bytes($bytes);
    }

    /**
     * Compare strings so that timing attacks are not feasible
     * @param string $a - hash
     * @param string $b - hash
     * @return boolean
     */
    public static function compare($a, $b)
    {
        $nonce = self::random(32);
        return \hash_hmac('sha256', $a, $nonce) === \hash_hmac('sha256', $b, $nonce);
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

}
