<?php
define('BASE', dirname(dirname(__DIR__)));
require_once BASE."/autoload.php";

$key = 'MtDK9NAiJ4Gi/WheP9/39w==';
$plain = 'YELLOW SUBMARINE';

$msg = \Resonantcore\Lib\Security\SAFE::encrypt($plain, $key);

echo $msg;
echo "\n";

$dec = \Resonantcore\Lib\Security\SAFE::decrypt($msg, $key);

echo $dec;
echo "\n";

/* THIS SHOULD FAIL */
try {
    $idx = strlen($msg) - mt_rand(0,31);
    $end = hexdec($msg[$idx]);
    $end += 8;
    $end %= 16;
    $msg[$idx] = dechex($end);
    
    $dec = \Resonantcore\Lib\Security\SAFE::decrypt($msg, $key);
    echo "OOPS! Invalid MAC didn't throw an exception. :( \n";
    echo $dec . "\n";
} catch (Exception $e) {
    echo "An intentionally bad MAC failed to validate.\n";
}
