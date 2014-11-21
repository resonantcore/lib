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
}
