<?php

namespace waytohealth\OAuth2\Client\Test\Provider;

use waytohealth\OAuth2\Client\Provider\Withings;
use League\OAuth2\Client\Token\AccessToken;
use Mockery;
use PHPUnit_Framework_TestCase as TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\RequestInterface;

class WithingsTest extends TestCase
{
    public static function callMethod($obj, $name, array $args) {
        $class = new \ReflectionClass($obj);
        $method = $class->getMethod($name);
        $method->setAccessible(true);
        return $method->invokeArgs($obj, $args);
    }

    protected $provider;

    protected function setUp()
    {
        $this->provider = new Withings([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);

        $this->token = new AccessToken([
            'access_token' => 'mock_token',
            'expires_in' => 10000
        ]);

    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl(['prompt' => 'mock_prompt']);
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('prompt', $query);
        $this->assertArrayNotHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes()
    {
        $scopes = ['user.info', 'user.metrics', 'user.activity'];

        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertContains(urlencode(implode(',', $scopes)), $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertEquals('/oauth2_user/authorize2', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);
        $this->assertEquals('/oauth2/token', $uri['path']);
    }

    public function testGetResourceOwnerDetailsUrl()
    {
        $url = $this->provider->getResourceOwnerDetailsUrl($this->token);
        $uri = parse_url($url);
        $this->assertEquals('/v2/user', $uri['path']);
        $this->assertEquals('action=getdevice&access_token=mock_token', $uri['query']);
    }

    public function testGetAccessToken()
    {
        $response = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token", "token_type":"Bearer", "scope": "identify"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testParsedResponseSuccess()
    {
        // When we have a successful response, we return the parsed response
        $successResponse = <<<RESPONSE
{
    "status": 0,
    "body": {
        "appli": 0,
        "callbackurl": "string",
        "expires": "string",
        "comment": "string"
    }
}
RESPONSE;

        $request = Mockery::mock(\Psr\Http\Message\RequestInterface::class);

        $response = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn($successResponse);
        $response->shouldReceive('getHeader')->andReturn('');

        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        $responseBody = $this->provider->getParsedResponse($request)['body'];
        $this->assertEquals($responseBody['expires'], "string");
    }

    public function testParsedResponseFailure()
    {
        // When the API responds with an error, we throw an exception
        // $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);

        $request = Mockery::mock(\Psr\Http\Message\RequestInterface::class);

        $response = Mockery::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"status":503,"error":"Invalid params"}');
        $response->shouldReceive('getHeader')->andReturn('');

        $client = Mockery::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        try {
            $this->provider->getParsedResponse($request);
            $this->fail('An exception should have been thrown');
        } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
            $this->assertEquals('Invalid params', $e->getMessage());
            $this->assertEquals(503, $e->getCode());
            // make sure response body is the parsed body
            $body = $e->getResponseBody();
            $this->assertTrue(is_array($body));
            $this->assertEquals(503, $body['status']);
            $this->assertEquals('Invalid params', $body['error']);
        }
    }

    public function testCreateResourceOwner()
    {
        $resourceOwner = $this->provider->createResourceOwner(
            ['userid' => 'value'], $this->token
        );

        $this->assertEquals($resourceOwner->getId(), 'value');
    }

    public function testRevoke()
    {
        $client = Mockery::spy('GuzzleHttp\ClientInterface');
        $this->provider->setHttpClient($client);

        $this->provider->revoke($this->token);

        $client->shouldHaveReceived('send')->with(
            Mockery::on(function ($argument) {
                $uri = $argument->getUri();
                $path = $uri->getPath() === "/notify";
                $query =  $uri->getQuery() === "action=revoke&token=".$this->token->getToken();
                return $path && $query;
            })
        );
    }

}
