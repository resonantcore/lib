<?php
namespace Resonantcore\Lib\Issues;

class Query extends \Exception
{
    protected $params = [];

    public function __construct($statement, $params = [])
    {
        $this->message = $statement;
        $this->params = $params;
    }

    public function getMessage()
    {
        return $this->message . "\n" \json_encode($this->params);
    }
}
