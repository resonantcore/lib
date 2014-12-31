<?php

class SecureTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\Lib\Secure::random()
     */
    public function testRandom()
    {
        $int = \Resonantcore\Lib\Secure::random(0,255);
        $this->assertTrue($int >= 0 && $int <= 255);
    }

    public function testBias()
    {
        $this->markTestSkipped('This test can fail randomly; only enable it when needed.');

        // Populate:
        $buffer = array_fill(0, 10, 0);

        // Perform the experiment:
        for ($i = 0; $i < 5000; ++$i) {
            // Increase a random index by 1
            $j = \Resonantcore\Lib\Secure::random(0, 9);
            ++$buffer[$j];
        }

        var_dump($buffer);

        // Analyze the results:
        for ($i = 0; $i < 10; ++$i) {
            // If any of these are 0, then our RNG is failing us
            $this->assertNotEquals($buffer[$i], 0);
        }
    }
}
