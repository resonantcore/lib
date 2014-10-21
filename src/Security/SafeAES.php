<?php

namespace Resonantcore\Lib\Security;
use \Resonantcore\Lib as Resonant;

# Copyright (c) 2014 Resonant Core, LLC. All rights reserved.
# Written by Scott Arciszewski

/**
 * Symmetric Authenticated & Fast Encryption using AES
 *
 * Summary: AES-128-CBC + HMAC-SHA-256, random IV, PBKDF2 if a separate key is provided.
 */
abstract class SafeAES
{
    const SEPARATOR = ':';
    const VERSION = 'A0';

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
        $_iv = Resonant\Secure::random($block_size);
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
            $_cipher,
            $_aKey,
            true
        );

        // Return an imploded array as a string
        return \implode(self::SEPARATOR, [
            self::VERSION,
            \base64_encode($_iv),
            \base64_encode($_cipher),
            \base64_encode($_mac)
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
        $_mac = \base64_decode($hmac);

        // Let's check our MAC
        if (!Resonant\Secure::compare($_mac, \hash_hmac($cf['hmac_algo'], $_cipher, $_aKey, true))) {
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
            self::getBlockSize(
                \strlen($_eKey)
            )
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
                return [
                    'block_mode' => MCRYPT_MODE_CBC,
                    'cipher' => 'aes',
                    'hmac_algo' => 'sha256',
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
     * @param string $verion
     * @return string
     */
    protected static function getAuthKey($base = null, $version = self::VERSION)
    {
        $cf = self::config($version);

        $l = \strlen($base);
        return \hash_pbkdf2($cf['pbkdf2_algo'], $base, 'authentication', $cf['pbkdf2_iterations'], $l, true);
    }

    /**
     * Use PBKDF2 to derive the encryption key for this $base.
     *
     * @param string $base
     * @param string $verion
     * @return string
     */
    protected static function getSecretKey($base = null, $version = self::VERSION)
    {
        $cf = self::config($version);

        $l = \strlen($base);
        return \hash_pbkdf2($cf['pbkdf2_algo'], $base, 'encryption', $cf['pbkdf2_iterations'], $l, true);
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
                switch($keylen)
                {
                    case 16:
                    case 24:
                    case 32:
                        return MCRYPT_RIJNDAEL_128;
                    default:
                        throw new \Exception("Unsupported key length: " . \strlen($key));
                }
            break;
            case 'twofish':
                return MCRYPT_TWOFISH;
            default:
                throw new \Exception("Unsupported key length: " . \strlen($key));
        }
    }

    /**
     * How large should our block be?
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
        $alg = self::getAlgorithm(\strlen($key), $version);

        return \mcrypt_encrypt(
            $alg,
            $key,
            $plaintext,
            $mode,
            $iv
        );
    }

    private static function decryptOnly($ciphertext, $key, $iv, $mode, $version = self::VERSION)
    {
        $alg = self::getAlgorithm(\strlen($key), $version);

        return \mcrypt_decrypt(
            $alg,
            $key,
            $ciphertext,
            $mode,
            $iv
        );
    }
}
