<?php

namespace waytohealth\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Withings extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Withings URL.
     *
     * @const string
     */
    const BASE_WITHINGS_URL = 'https://account.withings.com';

    /**
     * Withings API URL
     *
     * @const string
     */
    const BASE_WITHINGS_API_URL = 'https://wbsapi.withings.net';

    /**
     * HTTP header Accept-Language.
     *
     * @const string
     */
    const HEADER_ACCEPT_LANG = 'Accept-Language';

    /**
     * HTTP header Accept-Locale.
     *
     * @const string
     */
    const HEADER_ACCEPT_LOCALE = 'Accept-Locale';

    /**
     * @var string Key used in a token response to identify the resource owner.
     */
    const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'userid';

    /**
     * Get authorization url to begin OAuth flow.
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return static::BASE_WITHINGS_URL.'/oauth2_user/authorize2';
    }

    /**
     * Get access token url to retrieve token.
     *
     * @param array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return static::BASE_WITHINGS_API_URL.'/v2/oauth2';
    }

    /**
     * Requests an access token using a specified grant and option set.
     *
     * @param  mixed $grant
     * @param  array $options
     * @throws IdentityProviderException
     * @return AccessTokenInterface
     */
    public function getAccessToken($grant, array $options = [])
    {
        // withings requires the action to be 'requesttoken' when getting an access token
        if (empty($options['action'])) {
            $options['action'] = 'requesttoken';
        }

        return parent::getAccessToken($options);
    }

    /**
     * Returns the url to retrieve the resource owners's profile/details.
     *
     * @param AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return static::BASE_WITHINGS_API_URL.'/v2/user?action=getdevice&access_token='.$token->getToken();
    }

    /**
     * Returns all scopes available from Withings.
     * It is recommended you only request the scopes you need!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return ['user.info', 'user.metrics', 'user.activity'];
    }

    /**
     * Checks Withings API response for errors.
     *
     * @throws IdentityProviderException
     *
     * @param ResponseInterface $response
     * @param array|string      $data     Parsed response data
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if (array_key_exists('error', $data)) {
            $errorMessage = $data['error'];
            $errorCode = array_key_exists('status', $data) ?
                $data['status'] : $response->getStatusCode();
            throw new IdentityProviderException(
                $errorMessage,
                $errorCode,
                $data
            );
        }
    }

    /**
     * Prepares an parsed access token response for a grant.
     *
     * Custom mapping of expiration, etc should be done here. Always call the
     * parent method when overloading this method.
     *
     * @param  array $result
     * @return array
     */
    protected function prepareAccessTokenResponse(array $result)
    {
        if (!array_key_exists('status', $result)) {
            throw new IdentityProviderException(
                'Invalid response received from Authorization Server. Missing status.',
                0,
                $result
            );
        }

        if ($result['status'] !== 0) {
            throw new IdentityProviderException(
                sprintf('Invalid response received from Authorization Server. Status code %d.', $result['status']),
                0,
                $result
            );
        }

        if (!array_key_exists('body', $result)) {
            throw new IdentityProviderException(
                'Invalid response received from Authorization Server. Missing body.',
                0,
                $result
            );
        }

        return parent::prepareAccessTokenResponse($result['body']);
    }

    /**
     * Returns authorization parameters based on provided options.
     * Withings does not use the 'approval_prompt' param and here we remove it.
     *
     * @param array $options
     *
     * @return array Authorization parameters
     */
    protected function getAuthorizationParameters(array $options)
    {
        $params = parent::getAuthorizationParameters($options);
        unset($params['approval_prompt']);
        if (!empty($options['prompt'])) {
            $params['prompt'] = $options['prompt'];
        }

        return $params;
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param array       $response
     * @param AccessToken $token
     *
     * @return GenericResourceOwner
     */
    public function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, self::ACCESS_TOKEN_RESOURCE_OWNER_ID);
    }

    /**
     * Revoke access for the given token.
     *
     * @param AccessToken $accessToken
     *
     * @return mixed
     */
    public function revoke(AccessToken $accessToken)
    {
        $options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), []);
        $uri = $this->appendQuery(
            self::BASE_WITHINGS_API_URL.'/notify?action=revoke',
            $this->buildQueryString(['token' => $accessToken->getToken()])
        );
        $request = $this->getRequest(self::METHOD_POST, $uri, $options);

        return $this->getResponse($request);
    }

    public function parseResponse(ResponseInterface $response)
    {
        return parent::parseResponse($response);
    }
}
