# Withings Provider for OAuth 2.0 Client

This package provides Withings OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

This package is compliant with [PSR-1][], [PSR-2][], [PSR-4][], and [PSR-7][]. If you notice compliance oversights, please send a patch via pull request.

## Requirements

The following versions of PHP are supported.

* PHP 5.6
* PHP 7.0
* PHP 7.1
* HHVM

## Installation

To install, use composer:

```
composer require waytohealth/oauth2-withings
```

## Usage

### Authorization Code Grant

```php
use waytohealth\OAuth2\Client\Provider\Withings;

$provider = new Withings([
    'clientId'          => '{withings-oauth2-client-id}',
    'clientSecret'      => '{withings-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url'
]);

// start the session
session_start();

// If we don't have an authorization code then get one
if (!isset($_GET['code'])) {

    // Fetch the authorization URL from the provider; this returns the
    // urlAuthorize option and generates and applies any necessary parameters
    // (e.g. state).
    $authorizationUrl = $provider->getAuthorizationUrl();

    // Get the state generated for you and store it to the session.
    $_SESSION['oauth2state'] = $provider->getState();

    // Redirect the user to the authorization URL.
    header('Location: ' . $authorizationUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || array_key_exists('oauth2state', $_SESSION) && ($_GET['state'] !== $_SESSION['oauth2state'])) {
    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    try {

        // Try to get an access token using the authorization code grant.
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        // We have an access token, which we may use in authenticated
        // requests against the service provider's API.
        echo $accessToken->getToken() . "\n";
        echo $accessToken->getRefreshToken() . "\n";
        echo $accessToken->getExpires() . "\n";
        echo ($accessToken->hasExpired() ? 'expired' : 'not expired') . "\n";

        // Using the access token, we may look up details about the
        // resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);

        var_export($resourceOwner->toArray());

        // The provider provides a way to get an authenticated API request for
        // the service, using the access token; it returns an object conforming
        // to Psr\Http\Message\RequestInterface.
        $request = $provider->getAuthenticatedRequest(
            Withings::METHOD_GET,
            Withings::BASE_WITHINGS_API_URL . '/v2/user?action=getdevice',
            $accessToken,
            ['headers' => [Withings::HEADER_ACCEPT_LANG => 'en_US'], [Withings::HEADER_ACCEPT_LOCALE => 'en_US']]
            // Fitbit uses the Accept-Language for setting the unit system used
            // and setting Accept-Locale will return a translated response if available.
            // https://dev.fitbit.com/docs/basics/#localization
        );
        // Make the authenticated API request and get the parsed response.
        $response = $provider->getParsedResponse($request);

        // If you would like to get the response headers in addition to the response body, use:
        //$response = $provider->getResponse($request);
        //$headers = $response->getHeaders();
        //$parsedResponse = $provider->parseResponse($response);

    } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {

        // Failed to get the access token or user details.
        exit($e->getMessage());

    }

}
```

### Refreshing a Token

Once your application is authorized, you can refresh an expired token using a refresh token rather than going through the entire process of obtaining a brand new token. To do so, simply reuse this refresh token from your data store to request a refresh.

```php
$provider = new waytohealth\OAuth2\Client\Provider\Withings([
    'clientId'          => '{withings-oauth2-client-id}',
    'clientSecret'      => '{withings-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url'
]);

$existingAccessToken = getAccessTokenFromYourDataStore();

if ($existingAccessToken->hasExpired()) {
    $newAccessToken = $provider->getAccessToken('refresh_token', [
        'refresh_token' => $existingAccessToken->getRefreshToken()
    ]);

    // Purge old access token and store new access token to your data store.
}
```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/waytohealth/oauth2-withings/blob/master/CONTRIBUTING.md) for details.

## License

The MIT License (MIT). Please see [License File](https://github.com/waytohealth/oauth2-withings/blob/master/LICENSE) for more information.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md
[PSR-7]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-7-http-message.md
