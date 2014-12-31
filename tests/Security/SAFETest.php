<?php

class SAFETest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\Lib\Security\SAFE::encrypt()
     */
    public function testEncrypt()
    {
        $key = 'MtDK9NAiJ4Gi/WheP9/39w==';
        $plain = 'YELLOW SUBMARINE';

        $msg = \Resonantcore\Lib\Security\SAFE::encrypt($plain, $key);

        $this->assertEquals(
            1,
            preg_match('#^' .
                \Resonantcore\Lib\Security\SAFE::VERSION .
                \Resonantcore\Lib\Security\SAFE::SEPARATOR .
                '#', $msg
            )
        );

        return $msg;
    }
}
