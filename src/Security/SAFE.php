<?php
namespace Resonantcore\Lib\Security;

use \Resonantcore\Lib as Resonant;

# Copyright (c) 2014 Resonant Core, LLC. All rights reserved.
# Written by Scott Arciszewski

/**
 * Symmetric Authenticated & Fast Encryption
 */
abstract class SAFE
{
    const SEPARATOR = ':';
    const VERSION = 'B2';

    /**
     * Encrypt a message.
     *
     * @param string $plaintext - the plaintext message
     * @param string $key - base key for the encryption algorithm
     * @return string (a long one!)
     */
    public static function encrypt($plaintext, $key)
    {
        // Let's get our secret encryption and authentication keys...
        $_eKey = self::getSecretKey($key);
        $_aKey = self::getAuthKey($key);

        // Let's load the configration for new versions
        $cf = self::config();

        // How big of an IV do we need?
        $block_size = self::getBlockSize(\strlen($_eKey));

        // Let's generate an IV
        $_iv = Resonant\Secure::random_bytes($block_size);
        if ($_iv === false) {
            throw new \Exception("Random number generator failure!");
        }

        // Let's calculate the padded ciphertext
        $_cipher = self::encryptOnly(
            self::addPadding($plaintext, $block_size),
            $_eKey,
            $_iv,
            $cf['block_mode']
        );

        // Compute HMAC
        $_mac = \hash_hmac(
            $cf['hmac_algo'],
            $_iv . $_cipher,
            $_aKey,
            true
        );

        // Return an imploded array as a string
        return \implode(self::SEPARATOR, [
            self::VERSION,
            \base64_encode($_iv),
            \base64_encode($_cipher),
            \bin2hex($_mac)
        ]);
    }

    /**
     * Decrypts a message.
     *
     * @param string $ciphertext - version:iv:ciphertext:hmac
     * @param string $key - (optional) base key for the encryption algorithm
     ************************************************************************
     * @alternative
     *   @param string $ciphertext - the plaintext message
     *   @param string/null $key - the base key
     *   @param string $iv - initialization vector for CBC mode
     *   @param string $hmac - hash-based message authentication code
     *   @param string $version - version tag
     ************************************************************************
     * @return string (a long one!)
     */
    public static function decrypt(
        $ciphertext, // Both ways
        $key, // Both ways
        $iv = null, // Second way
        $hmac = null, // Second way
        $version = self::VERSION // Second way
    ) {
        $cf = self::config($version);

        // Let's unpack our message.
        if (!empty($iv) && !empty($hmac) && !empty($version)) {
            // Pass
            $cipher =& $ciphertext;
        } elseif (!\is_array($ciphertext)) {
            list($version, $iv, $cipher, $hmac) = \explode(self::SEPARATOR, $ciphertext);
        } else {
            throw new \Exception("Invalid ciphertext message.");
        }

        // Let's get our secret encryption and authentication keys...
        $_eKey = self::getSecretKey($key, $version);
        $_aKey = self::getAuthKey($key, $version);

        $block_size = self::getBlockSize(\strlen($_eKey));

        // Decode the paramaters
        $_iv = \base64_decode($iv);
        $_cipher = \base64_decode($cipher);
        switch ($version) {
            case 'A0':
            case 'A1':
                $_mac = \base64_decode($hmac);
                break;
            default:
                $_mac = \hex2bin($hmac);
                break;
        }

        // Let's check our MAC
        if (!\hash_equals(
            $_mac,
            \hash_hmac($cf['hmac_algo'], $_iv . $_cipher, $_aKey, true)
        )) {
            throw new \Exception("MAC validation failed!");
        }

        // If we're still kicking, let's decrypt and remove the padding.
        return self::removePadding(
            self::decryptOnly(
                $_cipher,
                $_eKey,
                $_iv,
                $cf['block_mode'],
                $version
            ),
            $block_size
        );
    }

    /**
     * Given a version tag, return the configuration settings. This allows us to
     * allocate new configurations with safer hash functions/parameters as new
     * cryptographic attacks are discovered over the years
     *
     * @param string
     * @return array
     */
    protected static function config($version = self::VERSION)
    {
        switch ($version) {
            case 'A0':
            case 'A1':
            case 'A2':
                return [
                    'driver' => 'mcrypt',
                    'block_mode' => MCRYPT_MODE_CBC,
                    'cipher' => 'aes',
                    'hmac_algo' => 'sha256',
                    'pbkdf2_algo' => 'sha256',
                    'pbkdf2_iterations' => 8000
                ];
            case 'B1':
                return [
                    'driver' => 'openssl',
                    'cipher' => 'aes',
                    'block_mode' => 'cbc',
                    'len_cipher_key' => 24,
                    'hmac_algo' => 'sha256',
                    'len_hmac_key' => 32,
                    'pbkdf2_algo' => 'sha256',
                    'pbkdf2_iterations' => 8000
                ];
            case 'B2':
                return [
                    'driver' => 'openssl',
                    'cipher' => 'aes',
                    'block_mode' => 'gcm',
                    'len_cipher_key' => 16,
                    'hmac_algo' => 'sha256',
                    'len_hmac_key' => 32,
                    'pbkdf2_algo' => 'sha256',
                    'pbkdf2_iterations' => 8000
                ];
            default:
                throw new \Exception("Unsupported version");
        }
    }

    /**
     * Use PBKDF2 to derive the authentication key for this $base.
     *
     * @param string $base
     * @param string $version
     * @return string
     */
    protected static function getAuthKey($base = null, $version = self::VERSION)
    {
        $cf = self::config($version);

        $l = isset($cf['len_hmac_key'])
                ? $cf['len_hmac_key']
                : \strlen($base);
        
        return \hash_pbkdf2(
            $cf['pbkdf2_algo'],
            $base,
            'authentication',
            $cf['pbkdf2_iterations'],
            $l,
            true
        );
    }

    /**
     * Use PBKDF2 to derive the encryption key for this $base.
     *
     * @param string $base
     * @param string $version
     * @return string
     */
    protected static function getSecretKey($base = null, $version = self::VERSION)
    {
        $cf = self::config($version);

        $l = isset($cf['len_cipher_key'])
                ? $cf['len_cipher_key']
                : \strlen($base);
        
        return \hash_pbkdf2(
            $cf['pbkdf2_algo'],
            $base,
            'encryption',
            $cf['pbkdf2_iterations'],
            $l,
            true
        );
    }

    /**
     * Returns the appropriate MCRYPT constant for a given version
     *
     * @param int $keylen - how large is the key (for non-AES block ciphers)?
     * @param string $version - which version of the config should we load?
     */
    protected static function getAlgorithm($keylen = 16, $version = self::VERSION)
    {
        $cf = self::config($version);

        switch(\strtolower($cf['cipher']))
        {
            case 'aes':
                if ($cf['driver'] === 'openssl') {
                    switch ($keylen) {
                        case 16:
                            return 'aes-128';
                        case 24:
                            return 'aes-192';
                        case 32:
                            return 'aes-256';
                        default:
                            throw new \Exception("Unsupported key length: " . $keylen);
                    }
                } else {
                    switch($keylen) {
                        case 16:
                        case 24:
                        case 32:
                            return MCRYPT_RIJNDAEL_128;
                    }
                }
            break;
            case 'twofish':
                return MCRYPT_TWOFISH;
        }
        throw new \Exception("Unsupported key length: " . $keylen);
    }

    /**
     * How large should our block be? Used for IV size generation.
     *
     * @param int $keylen - how long is the key? (for non-AES, this returns $keylen)
     * @param string $version - which version of the config should we load?
     */
    protected static function getBlockSize($keylen, $version = self::VERSION)
    {
        $cf = self::config($version);
        switch(\strtolower($cf['cipher']))
        {
            case 'aes':
                if ($cf['driver'] === 'openssl' && $cf['block_mode'] === 'gcm') {
                    return 12;
                }
                return 16;
            default:
                return $keylen;
        }
    }

    /**
     * Add appropriate padding to a ciphertext block.
     *
     * @param string $plaintext - unpadded plaintext message
     * @param string $block_size - the message should be padded to an even multiple of this
     * @return string
     */
    protected static function addPadding($plaintext, $block_size = 16)
    {
        $l = \strlen($plaintext) % $block_size;
        $l = $block_size - $l;
        $plaintext .= \str_repeat(chr($l), $l);
        return $plaintext;
    }

    /**
     * Remove PKCS#7 padding
     * @param $string - padded string
     * @param $string - unpaddded string
     */
    protected static function removePadding($plaintext)
    {
        $l = \strlen($plaintext) - ord($plaintext[\strlen($plaintext) - 1]);
        return \substr($plaintext, 0, $l);
    }

    private static function encryptOnly($plaintext, $key, $iv, $mode, $version = self::VERSION)
    {
        $cf = self::config($version);
        $alg = self::getAlgorithm(\strlen($key), $version);
        
        if ($cf['driver'] === 'openssl') {
            return \openssl_encrypt(
                $plaintext, 
                $alg.'-'.$cf['block_mode'],
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
        } else {
            return \mcrypt_encrypt(
                $alg,
                $key,
                $plaintext,
                $mode,
                $iv
            );
        }
    }

    private static function decryptOnly($ciphertext, $key, $iv, $mode, $version = self::VERSION)
    {
        $cf = self::config($version);
        $alg = self::getAlgorithm(\strlen($key), $version);

        if ($cf['driver'] === 'openssl') {
            return \openssl_decrypt(
                $ciphertext, 
                $alg.'-'.$cf['block_mode'],
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );
        } else {
            return \mcrypt_decrypt(
                $alg,
                $key,
                $ciphertext,
                $mode,
                $iv
            );
        }
    }
}
