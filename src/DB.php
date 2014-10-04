<?php
namespace Resonantcore\Lib;

class DB extends \PDO
{
    /**
     * Parameterized Query
     *
     * @param string $statement
     * @param array $params
     * @param const $fetch_style
     * @return mixed -- array if SELECT
     */
    public function dbQuery($statement, $params = [], $fetch_style = \PDO::FETCH_ASSOC)
    {
        if (empty($params)) {
            $stmt = $this->query($statement);
            if ($stmt !== false) {
                return $stmt->fetchAll($fetch_style);
            }
            return false;
        }
        $stmt = $this->prepare($statement);
        $exec = $stmt->execute($params);
        if ($exec) {
            return $stmt->fetchAll($fetch_style);
        }
        return false;
    }

    public function q($statement, ...$params)
    {
        return self::dbQuery($statement, $params);
    }

    /**
     * Fetch a single result -- useful for SELECT COUNT() queries
     *
     * @param string $statement
     * @param array $params
     * @return mixed
     */
    public function single($statement, $params = [])
    {
        $stmt = $this->prepare($statement);
        $exec = $stmt->execute($params);
        if ($exec) {
            return $stmt->fetchColumn(0);
        }
        return false;
    }

    /**
     * Iterate through every row in a table, executing a callback for each row
     *
     * @param string $table - Name of the table to operate on
     * @param function $func - Execute this on every row
     * @param string $sortby - Which clumn to sort by
     * @param boolean $descending -
     */
    public function iterate($table, callable $func, $select = '*', $sortby = null, $descending = false)
    {
        $dir = $descending ? 'DESC' : 'ASC';
        $query = "SELECT {$select} FROM " . $this->sanitize($table) .
                ( !empty($sortby)
                    ? " ORDER BY ".$this->sanitize($sortby).' '.$dir
                    : ""
                );
        $result = $this->dbQuery($query);
        if (empty($result)) {
            return false;
        }
        foreach($result as $row) {
            $func($row);
        }
    }

    public function sanitize($string)
    {
        return \substr($this->quote($string), 1, -1);
    }
}
