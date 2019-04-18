<?php

namespace Hobo\Authentication;

class Authentication_Request
{
    CONST API_VERSION = '1.0';
    CONST HMAC_ALGORITHM = 'sha256';
    const AUTH_PREFIX = 'auth_';
    CONST AUTH_VERSION = 'auth_version';
    CONST AUTH_KEY = 'auth_key';
    CONST AUTH_TIMESTAMP = 'auth_timestamp';
    CONST AUTH_SIGNATURE = 'auth_signature';

    protected $query_params = array();
    private $method;
    private $path;

    protected $auth_params = array(
        'auth_version' => NULL,
        'auth_key' => NULL,
        'auth_timestamp' => NULL,
        'auth_signature' => NULL
    );

    /**
     * Create a new instance of Request
     *
     * @param string $method
     * @param string $path
     * @param array  $params
     *
     * @return void
     */
    public function __construct($method, $path, array $params)
    {
        $this->method = strtoupper($method);
        $this->path = $path;
        $prefix_length = strlen(self::AUTH_PREFIX);
        foreach ($params as $k => $v) {
            $k = strtolower($k);
            substr($k, 0, $prefix_length) === self::AUTH_PREFIX ? $this->auth_params[$k] = $v : $this->query_params[$k] = $v;
        }
    }

    /**
     * Sign the request with a Token
     *
     * @param Authentication_Token $token
     *
     * @return array
     */
    public function sign_request(Authentication_Token $token): array
    {
        $this->auth_params = array(
            self::AUTH_VERSION => self::API_VERSION,
            self::AUTH_KEY => $token->get_key(),
            self::AUTH_TIMESTAMP => time()
        );

        $this->auth_params[self::AUTH_SIGNATURE] = $this->get_signature($token);
        return $this->auth_params;
    }

    /**
     * Parameter string
     *
     * @return string
     */
    protected function parameter_string(): string
    {
        $array = array();
        $params = array_merge($this->auth_params, $this->query_params);
        foreach ($params as $k => $v) {
            $array[strtolower($k)] = $v;
        }
        unset($array[self::AUTH_SIGNATURE]);
        return http_build_query($array);
    }

    /**
     * Get the hashed signature
     *
     * @param Authentication_Token $token
     *
     * @return string
     */
    protected function get_signature(Authentication_Token $token): string
    {
        $string_to_sign = implode("\n", array($this->method, $this->path, $this->parameter_string()));
        return hash_hmac(self::HMAC_ALGORITHM, $string_to_sign, $token->get_secret());
    }

    /**
     * @param Authentication_Token $token
     * @param int                  $timestamp_lifespan
     *
     * @return mixed
     * @throws Authentication_Exception
     */
    public function authenticate_request(Authentication_Token $token, $timestamp_lifespan = 600)
    {
        if ($this->auth_params[self::AUTH_KEY] === $token->get_key()) {
            return $this->authenticate_by_token($token, $timestamp_lifespan);
        }

        throw new Authentication_Exception('The ' . self::AUTH_KEY . ' is incorrect');
    }

    /**
     * @param Authentication_Token $token
     * @param int                  $timestamp_grace
     *
     * @return bool
     * @throws Authentication_Exception
     */
    protected function authenticate_by_token(Authentication_Token $token, $timestamp_grace = 600): bool
    {
        if (is_null($token->get_secret())) {
            throw new Authentication_Exception('The token secret is not set');
        }
        $this->validate_version();
        $this->validate_timestamp($timestamp_grace);
        $this->validate_signature($token);
        return TRUE;
    }

    /**
     * @return bool
     * @throws Authentication_Exception
     */
    protected function validate_version(): bool
    {
        if ($this->auth_params[self::AUTH_VERSION] !== self::API_VERSION) {
            throw new Authentication_Exception('The ' . self::AUTH_VERSION . ' is incorrect');
        }
        return TRUE;
    }

    /**
     * @param $timestamp_grace
     *
     * @return bool
     * @throws Authentication_Exception
     */
    protected function validate_timestamp($timestamp_grace): bool
    {
        if ($timestamp_grace == 0) {
            return TRUE;
        }
        $difference = $this->auth_params[self::AUTH_TIMESTAMP] - time();
        if ($difference >= $timestamp_grace) {
            throw new Authentication_Exception('The ' . self::AUTH_TIMESTAMP . ' is invalid');
        }
        return TRUE;
    }

    /**
     * @param Authentication_Token $token
     *
     * @return bool
     * @throws Authentication_Exception
     */
    protected function validate_signature(Authentication_Token $token): bool
    {
        if ($this->auth_params[self::AUTH_SIGNATURE] !== $this->get_signature($token)) {
            throw new Authentication_Exception('The ' . self::AUTH_SIGNATURE . ' is incorrect');
        }
        return TRUE;
    }
}
