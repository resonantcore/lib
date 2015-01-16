<?php
namespace Resonantcore\Lib\Security;

use \Resonantcore\Lib as Resonant;

/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014-2015 Resonant Core, LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **/

class CSRF
{
    const FORM_INDEX = '_CSRF_INDEX';
    const FORM_TOKEN = '_CSRF_TOKEN';
    const SESSION_INDEX = 'CSRF';
    const HASH_ALGO = 'sha256';
    const RECYCLE_AFTER = 100;

    public static $hmac_ip = true;

    /**
     * Insert a CSRF prevention token to a form
     * 
     * @param boolean $echo - output to stdout? If false, return a string.
     * @return string
     */
    public static function insertToken($echo = true)
    {
        $ret = '';
        if (!isset($_SESSION[self::SESSION_INDEX])) {
            $_SESSION[self::SESSION_INDEX] = [];
        }

        list($index, $token) = self::generateToken();

        $ret .= "<!--\n--><input type=\"hidden\" name=\"".self::FORM_INDEX."\" value=\"".Resonant\Secure::noHTML($index)."\" />";

        if (self::$hmac_ip !== false) {
            // Use HMAC to only allow this particular IP to send this request
            $token = \base64_encode(
                \hash_hmac(
                    self::HASH_ALGO,
                    isset($_SERVER['REMOTE_ADDR'])
                        ? $_SERVER['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($token),
                    true
                )
            );
        }


        $ret .= "<!--\n--><input type=\"hidden\" name=\"".self::FORM_TOKEN."\" value=\"".Resonant\Secure::noHTML($token)."\" />";
        if ($echo) {
            echo $ret;
            return '';
        }
        return $ret;
    }

    /**
     * Validate a request
     * @return boolean
     */
    public static function validateRequest()
    {
        if (!isset($_SESSION[self::SESSION_INDEX])) {
            $_SESSION[self::SESSION_INDEX] = [];
            return false;
        }

        if (!isset($_POST[self::FORM_INDEX]) || !isset($_POST[self::FORM_TOKEN])) {
            return false;
        }

        $index = $_POST[self::FORM_INDEX];
        $token = $_POST[self::FORM_TOKEN];

        if (!isset($_SESSION[self::SESSION_INDEX][$index])) {
            // CSRF Token not found
            return false;
        }
        $stored = $_SESSION[self::SESSION_INDEX][$index];

        // This is the expected token value
        if (self::$hmac_ip === false) {
            $expected = $stored['token'];
        } else {
            $expected = \base64_encode(
                \hash_hmac(
                    self::HASH_ALGO,
                    isset($_SERVER['REMOTE_ADDR'])
                        ? $_SERVER['REMOTE_ADDR']
                        : '127.0.0.1',
                    \base64_decode($stored['token']),
                    true
                )
            );
        }
        if (\hash_equals($token, $expected)) {
            unset($_SESSION[self::SESSION_INDEX][$index]);
            return true;
        } else {
            unset($_SESSION[self::SESSION_INDEX][$index]);
            return false;
        }

    }

    /**
     * Generate, store, and return the index and token
     * 
     * @return array [string, string]
     */
    protected static function generateToken()
    {
        $index = \base64_encode(Resonant\Secure::random_bytes(18));
        $token = \base64_encode(Resonant\Secure::random_bytes(32));

        $_SESSION[self::SESSION_INDEX][$index] = [
            'created' => \intval(\date('YmdHis')),
            'uri' => isset($_SERVER['REQUEST_URI'])
                ? $_SERVER['REQUEST_URI']
                : $_SERVER['SCRIPT_NAME'],
            'token' => $token
        ];

        self::recycleTokens();
        return [ $index, $token ];
    }
    
    /**
     * Enforce an upper limit on the number of tokens stored in session state
     * by removing the oldest tokens first.
     */
    protected static function recycleTokens()
    {
        // Sort by creation time
        \uasort($_SESSION[self::SESSION_INDEX], function($a, $b) {
            return $a['created'] - $b['created'];
        });

        if (\count($_SESSION[self::SESSION_INDEX]) > self::RECYCLE_AFTER) {
            // Let's knock off the oldest one
            \array_shift($_SESSION[self::SESSION_INDEX]);
        }
    }
}
