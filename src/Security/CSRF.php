<?php
namespace Resonantcore\Lib\Security;

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
    public static function insert_token($echo = true)
    {
        $ret = '';
        if (!isset($_SESSION[self::SESSION_INDEX])) {
            $_SESSION[self::SESSION_INDEX] = [];
        }

        list($index, $token) = self::_generateToken();

        $ret .= "<!--\n--><input type=\"hidden\" name=\"".self::FORM_INDEX."\" value=\"".\Resonantcore\Lib\Secure::noHTML($index)."\" />";

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


        $ret .= "<!--\n--><input type=\"hidden\" name=\"".self::FORM_TOKEN."\" value=\"".\Resonantcore\Lib\Secure::noHTML($token)."\" />";
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
    public static function validate_request()
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
    protected static function _generateToken()
    {
        $index = \base64_encode(\Resonantcore\Lib\Secure::random_bytes(18));
        $token = \base64_encode(\Resonantcore\Lib\Secure::random_bytes(32));

        $_SESSION[self::SESSION_INDEX][$index] = [
            'created' => \intval(\date('YmdHis')),
            'uri' => isset($_SERVER['REQUEST_URI'])
                ? $_SERVER['REQUEST_URI']
                : $_SERVER['SCRIPT_NAME'],
            'token' => $token
        ];

        self::_recycleTokens();
        return [ $index, $token ];
    }
    
    /**
     * Enforce an upper limit on the number of tokens stored in session state
     * by removing the oldest tokens first.
     */
    protected static function _recycleTokens()
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
