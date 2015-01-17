<?php

class CSRFTest extends PHPUnit_Framework_TestCase
{
    /**
     * @covers \Resonantcore\Lib\Security\CSRF::insert_token()
     */
    public function test_insert_token()
    {
        @session_start();

        ob_start();
        \Resonantcore\Lib\Security\CSRF::insertToken();
        $token_html = ob_get_clean();

        $this->assertFalse(
            empty($_SESSION[\Resonantcore\Lib\Security\CSRF::SESSION_INDEX])
        );
    }
}
