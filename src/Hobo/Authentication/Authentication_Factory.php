<?php

namespace Hobo\Authentication;

class Authentication_Factory
{
    /**
     * @param      $key
     * @param null $secret
     *
     * @return \Hobo\Authentication\Authentication_Token
     */
    public function get_token($key, $secret = NULL): Authentication_Token
    {
        return new Authentication_Token($key, $secret);
    }

    /**
     * Request
     *
     * @param string $method
     * @param string $path
     * @param array  $params
     *
     * @return Authentication_Request
     */
    public function get_request($method, $path, array $params): Authentication_Request
    {
        return new Authentication_Request($method, $path, $params);
    }

}
