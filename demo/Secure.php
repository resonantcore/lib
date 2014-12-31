<?php
define('BASE', dirname(__DIR__));
require_once BASE."/autoload.php";

echo "# Demo: \Resonantcore\Lib\Secure\n\n";

/* Secure::random($min, $max) */
echo "\n## random(\$min, \$max)\n";

$charset = array_merge(range('a', 'z'), range('2', '7'));
$buffer = '';

for ($i = 0; $i < 16; ++$i) {
    // Get a random index
    $n = \Resonantcore\Lib\Secure::random(0, 31);

    // Append a random character from $charset to buffer
    $buffer .= $charset[$n];
}
echo $buffer . "\n";
unset($buffer);

/* Secure::random_bytes($num) */
echo "\n## random_bytes(\$num)\n";

echo base64_encode(\Resonantcore\Lib\Secure::random_bytes(32)) . "\n";

/* Secure::noHTML($str) */
echo "\n## noHTML(\$str)\n";

$buffer = \Resonantcore\Lib\Secure::noHTML('<br />');
if ($buffer === '&lt;br /&gt') {
    echo "No HTML succeeded!\n";
}
unset($buffer);

/* Secure::file_valid($file, $jail_dir) */
echo "\n## file_valid(\$file, \$jail_dir)\n";

$buffer = \Resonantcore\Lib\Secure::file_valid($_SERVER['PHP_SELF'], BASE);
var_dump($buffer);
unset($buffer);

/* Secure::random_positive_int() */
echo "\n## random_positive_int()\n";

$buffer = \Resonantcore\Lib\Secure::random_positive_int();
var_dump($buffer);
unset($buffer);
