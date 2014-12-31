<?php
namespace Resonantcore\Lib;

class Utility
{
    public static function getJSON($file)
    {
        if (\is_readable($file)) {
            return self::parseJSON(\file_get_contents($file), true);
        }
    }

    public static function parseJSON($json, $assoc = false, $depth = 512, $options = 0)
    {
        return json_decode(
            preg_replace(
                "#(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|([\s\t]//.*)|(^//.*)#",
                '',
                $json
            ),
            $assoc,
            $depth,
            $options
        );
    }

    /**
     * This is superior to the native utf8_encode function
     *
     * @param string $string String of unknown encoding
     * @param string $from_type (optional) Specify the input encoding
     * @return string
     */
    public static function toUTF8($string, $from_type = null)
    {
        if (empty($from_type)) {
            $from_type = \mb_detect_encoding($string);
            if ($from_type === 'UTF-8') {
                // No operation needed...
                return $string;
            }
        }
        return \mb_convert_encoding($string, 'UTF-8', $from_type);
    }

    /**
     * This is superior to the native utf8_encode function
     *
     * @param string $string UTF-8 encoded string
     * @param string $from_type Specify the output encoding
     * @return string
     */
    public static function fromUTF8($string, $to_type = 'ISO-8859-1')
    {
        return \mb_convert_encoding($string, $to_type, 'UTF-8');
    }
}
