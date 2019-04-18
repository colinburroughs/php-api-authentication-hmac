<?php

namespace Hobo\Authentication;

class Authentication_Token
{
    /**
     * The key
     *
     * @var string
     */
    protected $key;

    /**
     * The secret
     *
     * @var string
     */
    protected $secret;

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
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * Get the key
     *
     * @return string
     */
    public function get_key()
    {
        return $this->key;
    }

    /**
     * Get the secret
     *
     * @return string
     */
    public function get_secret()
    {
        return $this->secret;
    }

}
