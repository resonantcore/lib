<?php
namespace Resonantcore\Lib;

use \Resonantcore\Lib\Issues as ResonantIssue;

/**
 * The MIT License (MIT)
 * 
 * Copyright (c) 2014-2015 Resonant Core, LLC
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 **/

class DB extends \PDO
{
    public $dbengine = null;
    
    public function __construct($dsn, $username, $password, $options = [])
    {
        $post_query = null;

        // Let's grab the DB engine
        if (strpos($dsn, ':') !== false) {
            $this->dbengine = explode(':', $dsn)[0];
        }

        // If no charset is specified, default to UTF-8
        switch ($this->dbengine) {
            case 'mysql':
                if (strpos($dsn, ';charset=') === false) {
                    $dsn .= ';charset=utf8';
                }
                break;
            case 'pgsql':
                $post_query = 'SET NAMES UNICODE';
                break;
        }

        // Let's call the parent constructor now
        parent::__construct($dsn, $username, $password, $options);

        // Let's turn off emulated prepares
        $this->setAttribute(\PDO::ATTR_EMULATE_PREPARES, false);

        if (!empty($post_query)) {
            $this->query($post_query);
        }
    }
    
    /**
     * Variadic version of $this->column()
     *
     * @param string $statement SQL query without user data
     * @param int $offset - How many columns from the left are we grabbing from each row?
     * @params ... $params Parameters
     * @return mixed
     */
    public function col($statement, ...$params)
    {
        return self::column($statement, $params);
    }
    
    /**
     * Fetch a column
     * 
     * @param string $statement SQL query without user data
     * @param int $offset - How many columns from the left are we grabbing from each row?
     * @params ... $params Parameters
     * @return mixed
     */
    public function column($statement, $params = [], $offset = 0)
    {
        // This array accumulates our results
        $columns = [];
        
        $stmt = $this->prepare($statement);
        $exec = $stmt->execute($params);
        if ($exec) {
            do {
                $curr = $stmt->fetchColumn($offset);
                if ($curr === false) {
                    break;
                }
                $columns[] = $curr;
            } while($curr !== false);
            return $curr;
        }
        return false;
    }
    
    /**
     * Variadic version of $this->single()
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     * @return mixed
     */
    public function cell($statement, ...$params)
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
        if ($exec === false) {
            throw new ResonantIssue\Query($statement, $params);
        }
        return $stmt->fetchAll($fetch_style);
    }
    
    /**
     * Delete rows in a database table.
     *
     * @param string $table - table name
     * @param array $conditions - WHERE clause
     */
    public function delete($table, array $conditions)
    {
        if (empty($changes) || empty($conditions)) {
            return null;
        }
        $queryString = "DELETE FROM ".$this->escapeIdentifier($table)." WHERE ";
        
        // Simple array for joining the strings together
        $arr = [];
        foreach ($conditions as $i => $v) {
            $i = $this->escapeIdentifier($i);
            $arr []= " {$i} = ? ";
            $params[] = $v;
        }
        $queryString .= \implode(' AND ', $arr);

        return $this->dbQuery($queryString, $params);
    }
    
    /**
     * Make sure only valid characters make it in column/table names
     * 
     * @ref https://stackoverflow.com/questions/10573922/what-does-the-sql-standard-say-about-usage-of-backtick
     * 
     * @param string $string - table or column name
     * @param boolean $quote - certain SQLs escape column names (i.e. mysql with `backticks`)
     * @return string
     */
    public function escapeIdentifier($string, $quote = true)
    {
        // Force UTF-8
        // Strip out invalid characters
        $str = \preg_replace(
            '/[^0-9a-zA-Z_]/',
            '',
            \Resonantcore\Lib\Utility::toUTF8($string)
        );
        
        // The first character cannot be [0-9]:
        if (\preg_match('/^[0-9]/', $str)) {
            // FATAL ERROR
            \trigger_error("Invalid identifier: Must begin with a letter or undescore.", E_USER_ERROR);
        }
        
        if ($quote) {
            switch ($this->dbengine) {
                case 'mssql':
                    return '['.$str.']';
                case 'mysql':
                    return '`'.$str.'`';
                default:
                    return '"'.$str.'"';
            }
        }
        return $str;
    }

    /**
     * Iterate through every row in a table, executing a callback for each row
     *
     * @param string $table - Name of the table to operate on
     * @param function $func - Execute this on every row
     * @param array $where - Conditions on the SELECT query
     * @param string $sortby - Which clumn to sort by
     * @param boolean $descending - Should we sort up or down?
     * @return array
     */
    public function forEachRow(
        $table,
        callable $func,
        $select = '*',
        $where = null,
        $sortby = null,
        $descending = false
    ) {
        $dir = $descending ? 'DESC' : 'ASC';
        $query = "SELECT {$select} FROM ".$this->escapeIdentifier($table)." ";
        
        // If $where is provided, we'll use this.
        $queryParams = [];
        
        if (!empty($where)) {
            if (is_string($where)) {
                // Boring!
                $query .= " WHERE " . $where;
            } elseif (is_array($where)) {
                $query .= " WHERE ";
                $conditions = [];
                foreach ($where as $key => $value) {
                    // Add a placeholder
                    $conditions[] = $this->escapeIdentifier($key).' = ?';
                    // Append this value
                    $queryParams[] = $value;
                }
                $query .= \implode(' AND ', $conditions);
            }
        }
        
        // How should we sort the data?
        if (!empty($sortby)) {
            $query .= " ORDER BY ".$this->escapeIdentifier($sortby).' '.$dir;
        }

        $result = $this->dbQuery($query, $queryParams);
        if (empty($result)) {
            // No results!
            return false;
        }
        foreach($result as $i => $row) {
            $result[$i] = $func($row);
        }
        return $result;
    }

    /**
     * Insert a new row to a table in a database.
     *
     * @param string $table - table name
     * @param array $changes - associative array of which values should be assigned to each field
     */
    public function insert($table, array $map)
    {
        if (empty($map)) {
            return null;
        }

        // Begin query string
        $queryString = "INSERT INTO ".$this->escapeIdentifier($table)." (";

        // Let's make sure our keys are escaped.
        $keys = \array_keys($map);
        foreach ($keys as $i => $v) {
            $keys[$i] = $this->escapeIdentifier($v);
        }

        // Now let's append a list of our columns.
        $queryString .= \implode(', ', $keys);

        // This is the middle piece.
        $queryString .= ") VALUES (";

        // Now let's concatenate the ? placeholders
        $queryString .= \implode(', ', \array_fill(0, \count($map), '?'));

        // Necessary to close the open ( above
        $queryString .= ");";

        // Now let's run a query with the parameters
        return $this->dbQuery($queryString, \array_values($map));
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
     * PHP 5.6 variadic shorthand for $this->dbQuery()
     *
     * @param string $statement SQL query without user data
     * @params mixed ...$params Parameters
     * @return mixed - If successful, a 2D array
     */
    public function run($statement, ...$params)
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
        if ($exec === false) {
            throw new ResonantIssue\Query($statement, $params);
        }
        return $stmt->fetchColumn(0);
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
        $queryString = "UPDATE ".$this->escapeIdentifier($table)." SET ";
        
        // The first set (pre WHERE)
        $pre = [];
        foreach ($changes as $i => $v) {
            $i = $this->escapeIdentifier($i);
            $pre []= " {$i} = ?";
            $params[] = $v;
        }
        $queryString .= \implode(', ', $pre);
        $queryString .= " WHERE ";
        
        // The last set (post WHERE)
        $post = [];
        foreach ($conditions as $i => $v) {
            $i = $this->escapeIdentifier($i);
            $post []= " {$i} = ? ";
            $params[] = $v;
        }
        $queryString .= \implode(' AND ', $post);

        return $this->dbQuery($queryString, $params);
    }
}
