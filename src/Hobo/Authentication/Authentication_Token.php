<?php

namespace Hobo\Authentication;

class Authentication_Token
{
    /**
     * The key
     *
     * @var string
     */
    protected $_key;

    /**
     * The secret
     *
     * @var string
     */
    protected $_secret;

    /**
     * Create a new instance of Token
     *
     * @param string $key
     * @param string $secret
     *
     * @return void
     */
    public function __construct($key, $secret)
    {
        $this->_key = $key;
        $this->_secret = $secret;
    }

    /**
     * Get the key
     *
     * @return string
     */
    public function get_key()
    {
        return $this->_key;
    }

    /**
     * Get the secret
     *
     * @return string
     */
    public function get_secret()
    {
        return $this->_secret;
    }

}
