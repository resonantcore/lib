<?php

class UtilityTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\Lib\Utility::toUTF8()
     */
    public function testToUTF8()
    {
        // Invalid UTF-8
        $bad = "\xff\x27 Something";
        $cleaned = \Resonantcore\Lib\Utility::toUTF8($bad);

        $this->assertFalse(strpos($cleaned, "\xff\x27"));
    }
}
