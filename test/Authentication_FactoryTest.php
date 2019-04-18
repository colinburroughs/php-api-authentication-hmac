<?php

use Hobo\Authentication\Authentication_Exception;
use Hobo\Authentication\Authentication_Factory;
use Hobo\Authentication\Authentication_Request;
use PHPUnit\Framework\TestCase;

class Authentication_FactoryTest extends TestCase
{
    const API_KEY = 'my_key';
    const API_SECRET = 'my_secret';
    const API_SECRET_NULL = NULL;
    const API_SECRET_LONG = 'The quick brown fox jumps over the lazy dog';
    const API_VERSION_INCORRECT = '0.0';
    const REQUEST_METHOD_POST = 'POST';
    const REQUEST_METHOD_GET = 'GET';
    const PATH_STANDARD = '/api/path';
    const PATH_NOT_STANDARD = '/no/api/path';

    private function build_simple_api_request()
    {
        $factory = new Authentication_Factory();
        $params = array('name' => 'Arbitrary Name', 'email' => 'email.address@this.domain.net');
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $params);
        $auth_params = $request->sign_request($token);
        return array_merge($params, $auth_params);
    }

    /**
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authenticate_request_success()
    {
        $factory = new Authentication_Factory();
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $this->build_simple_api_request());
        $this->assertTrue($request->authenticate_request($token));
    }

    /**
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authenticate_request_different_method()
    {
        $factory = new Authentication_Factory();
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $request = $factory->get_request(self::REQUEST_METHOD_GET, self::PATH_STANDARD, $this->build_simple_api_request());
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authenticate_request_different_path()
    {
        $factory = new Authentication_Factory();
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $request = $factory->get_request('GET', self::PATH_NOT_STANDARD, $this->build_simple_api_request());
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @expectedExceptionMessage The auth_key is incorrect
     *
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authentication_request_incorrect_key()
    {
        $factory = new Authentication_Factory();
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $this->build_simple_api_request());
        $token = $factory->get_token('not_my_key', self::API_SECRET);
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @expectedExceptionMessage The token secret is not set
     *
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authentication_request_incorrect_secret()
    {
        $factory = new Authentication_Factory();
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $this->build_simple_api_request());
        $token = $factory->get_token(self::API_KEY, self::API_SECRET_NULL);
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @expectedExceptionMessage The auth_version is incorrect
     *
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authentication_request_incorrect_version()
    {
        $factory = new Authentication_Factory();
        $params = $this->build_simple_api_request();
        $params[Authentication_Request::AUTH_VERSION] = self::API_VERSION_INCORRECT;
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $params);
        $token = $factory->get_token(self::API_KEY, 'not_my_secret');
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @expectedExceptionMessage The auth_timestamp is invalid
     *
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authentication_request_incorrect_timestamp()
    {
        $factory = new Authentication_Factory();
        $params = $this->build_simple_api_request();
        $params[Authentication_Request::AUTH_TIMESTAMP] = time() + (7 * 24 * 60 * 60);
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $params);
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }

    /**
     * @expectedExceptionMessage The auth_signature is incorrect
     *
     * @throws \Hobo\Authentication\Authentication_Exception
     */
    public function test_authentication_request_incorrect_signature()
    {
        $factory = new Authentication_Factory();
        $params = $this->build_simple_api_request();
        $params[Authentication_Request::AUTH_SIGNATURE] = self::API_SECRET_LONG;
        $request = $factory->get_request(self::REQUEST_METHOD_POST, self::PATH_STANDARD, $params);
        $token = $factory->get_token(self::API_KEY, self::API_SECRET);
        $this->expectException(Authentication_Exception::class);
        $request->authenticate_request($token);
    }
}
