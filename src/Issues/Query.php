<?php
namespace Resonantcore\Lib\Issues;

class Query extends \Exception
{
    protected $params = [];

    public function __construct($statement, $params = [], $code = 0, \Exception $previous = NULL)
    {
        $this->params = $params;
        parent::__construct($statement, $code, $previous);
    }

    public function getMessage()
    {
        return $this->message . "\n" . \json_encode($this->params);
    }
}
