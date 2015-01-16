<?php
namespace Resonantcore\Lib;

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

class Utility
{
    /**
     * Read a JSON file, return its contents as an array
     *
     * @param string $file file name
     * @return mixed (array on success, null on failure)
     */
    public static function getJSON($file)
    {
        if (\is_readable($file)) {
            return self::parseJSON(\file_get_contents($file), true);
        }
        return null;
    }

    /**
     * Parser for JSON with comments
     *
     * @param string $json JSON text
     * @param boolean $assoc Return as an associative array?
     * @param int $depth Maximum depth
     * @param int $options options
     * @return mixed
     */
    public static function parseJSON($json, $assoc = false, $depth = 512, $options = 0)
    {
        return \json_decode(
            \preg_replace(
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
            $from_type = \mb_detect_encoding($string, 'auto');
            if ($from_type === false) {

                // Let's get rid of all non-UTF8 chars
                return \preg_replace(
                    '/[\x00-\x08\x10\x0B\x0C\x0E-\x19\x7F]'.
                        '|[\x00-\x7F][\x80-\xBF]+'.
                        '|([\xC0\xC1]|[\xF0-\xFF])[\x80-\xBF]*'.
                        '|[\xC2-\xDF]((?![\x80-\xBF])|[\x80-\xBF]{2,})'.
                        '|[\xE0-\xEF](([\x80-\xBF](?![\x80-\xBF]))|(?![\x80-\xBF]{2})|[\x80-\xBF]{3,})/S',
                    '?',
                    $string
                );
            } elseif ($from_type === 'UTF-8') {
                // Let's get rid of all non-UTF8 chars
                return \preg_replace(
                    '/[\x00-\x08\x10\x0B\x0C\x0E-\x19\x7F]'.
                        '|[\x00-\x7F][\x80-\xBF]+'.
                        '|([\xC0\xC1]|[\xF0-\xFF])[\x80-\xBF]*'.
                        '|[\xC2-\xDF]((?![\x80-\xBF])|[\x80-\xBF]{2,})'.
                        '|[\xE0-\xEF](([\x80-\xBF](?![\x80-\xBF]))|(?![\x80-\xBF]{2})|[\x80-\xBF]{3,})/S',
                    '?',
                    $string
                );
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
