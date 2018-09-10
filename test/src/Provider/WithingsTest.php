<?php

namespace waytohealth\OAuth2\Client\Test\Provider;

use waytohealth\OAuth2\Client\Provider\Withings;
use League\OAuth2\Client\Token\AccessToken;
use Eloquent\Phony\Phpunit\Phony;
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

        $this->mockClient = Phony::mock(\GuzzleHttp\ClientInterface::class);
        $this->provider->setHttpClient($this->mockClient->get());

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

        $requestMock = Phony::mock(\Psr\Http\Message\RequestInterface::class)->get();

        $this->mockClient->send->returns(
            new \GuzzleHttp\Psr7\Response(200, [], $successResponse)
        );
        $this->assertEquals($this->provider->getParsedResponse($requestMock)['body']['expires'], "string");
    }

    public function testParsedResponseFailure()
    {
        $requestMock = Phony::mock(\Psr\Http\Message\RequestInterface::class)->get();

        // When the API responds with an error, we throw an exception
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);

        $this->mockClient->send->returns(
            new \GuzzleHttp\Psr7\Response(200, [], '{"status":503,"error":"Test error"}')
        );
        $this->provider->getParsedResponse($requestMock);
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
        $this->provider->revoke($this->token);

        $args = $this->mockClient->send
            ->allCalls()[0]
            ->firstEvent()
            ->arguments();

        $calledUri = $args->get(0)->getUri();
        $this->assertEquals($calledUri->getQuery(), "action=revoke&token=mock_token");
    }

}
