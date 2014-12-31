<?php
namespace Resonantcore\Lib;

class DB extends \PDO
{
    public $dbengine = null;
    
    public function __construct($dsn, $username, $password, $options = [])
    {
        if (strpos($dsn, ':') !== false) {
            $this->dbengine = explode(':', $dsn)[0];
        }
        parent::__construct($dsn, $username, $password, $options);
    }
    
    /**
     * Variadic version of $this->single()
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     * @return mixed
     */
    public function col($statement, ...$params)
    {
        return self::single($statement, $params);
    }
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
    
    /**
     * Make sure only valid characters make it in column/table names
     * 
     * @ref https://stackoverflow.com/questions/10573922/what-does-the-sql-standard-say-about-usage-of-backtick
     * 
     * @param string $str - column name
     * @param boolean $quote - certain SQLs escape column names (i.e. mysql with `backticks`)
     * @return string
     */
    public function escape_identifier($str, $quote = true)
    {
        // Force UTF-8
        $str = \Resonantcore\Lib\Utility::toUTF8($str);

        // Strip out invalid characters
        $str = \preg_replace('/[^0-9a-zA-Z_]/', '', $str);
        
        // The first character cannot be [0-9]:
        if (\preg_match('/^[0-9]/', $str)) {
            throw new \PDOException("Invalid identifier: Must begin with a letter or undescore.");
        }
        if ($quote) {
            switch ($this->dbengine) {
                case 'mssql':
                    return '[' . $str . ']';
                case 'mysql':
                    return '`' . $str . '`';
                default:
                    return '"' . $str . '"';
            }
        }
        return $str;
    }

    /**
     * Insert a new row to a table in a database.
     *
     * @param string $table - table name
     * @param array $changes - associative array of which values should be assigned to each field
     * @param array $conditions - WHERE clause
     */
    public function insert($table, array $map)
    {
        if (empty($map)) {
            return null;
        }
        $queryString = "INSERT INTO " . $this->escape_identifier($table) . " (";
        
            // Let's make sure our keys are escaped.
            $keys = \array_keys($map);
            foreach ($keys as $i => $v) {
                $keys[$i] = $this->escape_identifier($v);
            }
            $queryString .= \implode(', ', $keys);
        $queryString .= ") VALUES (";
            $queryString .= \implode(', ', \array_fill(0, \count($map), '?'));
        $queryString .= ");";
        return $this->dbQuery($queryString, \array_values($map));
    }

    /**
     * Iterate through every row in a table, executing a callback for each row
     *
     * @param string $table - Name of the table to operate on
     * @param function $func - Execute this on every row
     * @param string $sortby - Which clumn to sort by
     * @param boolean $descending - Should we sort up or down?
     */
    public function iterate($table, callable $func, $select = '*', $sortby = null, $descending = false)
    {
        $dir = $descending ? 'DESC' : 'ASC';
        $query = "SELECT {$select} FROM " . $this->escape_identifier($table) .
                ( !empty($sortby)
                    ? " ORDER BY ".$this->escape_identifier($sortby).' '.$dir
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

    /**
     * PHP 5.6 variadic shorthand for $this->dbQuery()
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     */
    public function q($statement, ...$params)
    {
        return self::dbQuery($statement, $params);
    }

    /**
     * Similar to $this->q() except it only returns a single row
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     */
    public function row($statement, ...$params)
    {
        $result = self::dbQuery($statement, $params);
        if (\is_array($result)) {
            return \array_shift($result);
        }
        return [];
    }

    /**
     * Manually escape data for insertion into an SQL query (NOT RECOMMENDED!)
     * @param string $string input string
     * @return string
     */
    public function sanitize($string)
    {
        return \substr($this->quote($string), 1, -1);
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
     * Update a row in a database table.
     *
     * @param string $table - table name
     * @param array $changes - associative array of which values should be assigned to each field
     * @param array $conditions - WHERE clause
     */
    public function update($table, array $changes, array $conditions)
    {
        if (empty($changes) || empty($conditions)) {
            return null;
        }
        $queryString = "UPDATE " . $this->escape_identifier($table) . " SET ";
        
        // The first set (pre WHERE)
        $pre = [];
        foreach ($changes as $i => $v) {
            $i = $this->escape_identifier($i);
            $pre []= " {$i} = ?";
            $params[] = $v;
        }
        $queryString .= \implode(', ', $pre);
        $queryString .= " WHERE ";
        
        // The last set (post WHERE)
        $post = [];
        foreach ($conditions as $i => $v) {
            $i = $this->escape_identifier($i);
            $post []= " {$i} = ? ";
            $params[] = $v;
        }
        $queryString .= \implode(' AND ', $post);

        return $this->dbQuery($queryString, $params);
    }
}
