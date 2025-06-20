<?php
/*
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

namespace MediaWiki\Extension\OpenIDConnect;

use Config;
use Exception;
use Jumbojett\OpenIDConnectClient;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\PluggableAuth\BackchannelLogoutAwarePlugin;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Rest\RequestInterface;
use MediaWiki\Rest\ResponseInterface;
use MediaWiki\Rest\StringStream;
use MediaWiki\Session\SessionManager;
use MediaWiki\Session\SessionManagerInterface;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserIdentityLookup;
use MediaWiki\User\UserNameUtils;
use SpecialPage;
use TitleFactory;
use Wikimedia\Assert\Assert;
use Wikimedia\UUID\GlobalIdGenerator;

class OpenIDConnect extends PluggableAuth implements BackchannelLogoutAwarePlugin {

	/**
	 * @var Config
	 */
	private $mainConfig;

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var OpenIDConnectClient
	 */
	private $openIDConnectClient;

	/**
	 * @var UserIdentityLookup
	 */
	private $userIdentityLookup;

	/**
	 * @var UserNameUtils
	 */
	private $userNameUtils;

	/**
	 * @var OpenIDConnectStore
	 */
	private $openIDConnectStore;

	/**
	 * @var TitleFactory
	 */
	private $titleFactory;

	/**
	 * @var GlobalIdGenerator
	 */
	private $globalIdGenerator;

	/**
	 * @var UserFactory
	 */
	private $userFactory;

	/**
	 * @var bool
	 */
	private $migrateUsersByEmail;

	/**
	 * @var bool
	 */
	private $migrateUsersByUserName;

	/**
	 * @var bool
	 */
	private $singleLogout;

	/**
	 * @var bool
	 */
	private $forceReauth;

	/**
	 * @var bool
	 */
	private $useRealNameAsUserName;

	/**
	 * @var bool
	 */
	private $useEmailNameAsUserName;

	/**
	 * @var bool
	 */
	private $useRandomUsernames;

	/**
	 * @var callable
	 */
	private $realNameProcessor;

	/**
	 * @var callable
	 */
	private $emailProcessor;

	/**
	 * @var callable
	 */
	private $preferredUsernameProcessor;

	/**
	 * @var string
	 */
	private $subject;

	/**
	 * @var string
	 */
	private $issuer;

	const OIDC_SUBJECT_SESSION_KEY = 'OpenIDConnectSubject';
	const OIDC_ISSUER_SESSION_KEY = 'OpenIDConnectIssuer';
	const OIDC_ACCESSTOKEN_SESSION_KEY = 'OpenIDConnectAccessToken';
	const OIDC_ACCESSTOKENFULL_SESSION_KEY = 'OpenIDConnectFullAccessToken';
	const OIDC_IDTOKEN_SESSION_KEY = 'OpenIDConnectIdToken';
	const OIDC_IDTOKENPAYLOAD_SESSION_KEY = 'OpenIDConnectIdTokenPayload';
	const OIDC_REFRESHTOKEN_SESSION_KEY = 'OpenIDConnectRefreshToken';

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param OpenIDConnectClient $openIDConnectClient
	 * @param UserIdentityLookup $userIdentityLookup
	 * @param UserNameUtils $userNameUtils
	 * @param OpenIDConnectStore $openIDConnectStore
	 * @param TitleFactory $titleFactory
	 * @param GlobalIdGenerator $globalIdGenerator
	 * @param UserFactory $userFactory
	 */
	public function __construct(
		Config $mainConfig,
		AuthManager $authManager,
		OpenIDConnectClient $openIDConnectClient,
		UserIdentityLookup $userIdentityLookup,
		UserNameUtils $userNameUtils,
		OpenIDConnectStore $openIDConnectStore,
		TitleFactory $titleFactory,
		GlobalIdGenerator $globalIdGenerator,
		UserFactory $userFactory
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->openIDConnectClient = $openIDConnectClient;
		$this->userIdentityLookup = $userIdentityLookup;
		$this->userNameUtils = $userNameUtils;
		$this->openIDConnectStore = $openIDConnectStore;
		$this->titleFactory = $titleFactory;
		$this->globalIdGenerator = $globalIdGenerator;
		$this->userFactory = $userFactory;
	}

	/**
	 * @param string $configId
	 * @param array $config
	 * @return void
	 */
	public function init( string $configId, array $config ): void {
		parent::init( $configId, $config );
		$this->migrateUsersByEmail = $this->getConfigValue( 'MigrateUsersByEmail' );
		$this->migrateUsersByUserName = $this->getConfigValue( 'MigrateUsersByUserName' );
		$this->forceReauth = $this->getConfigValue( 'ForceReauth' );
		$this->singleLogout = $this->getConfigValue( 'SingleLogout' );
		$this->useRealNameAsUserName = $this->getConfigValue( 'UseRealNameAsUserName' );
		$this->useEmailNameAsUserName = $this->getConfigValue( 'UseEmailNameAsUserName' );
		$this->useRandomUsernames = $this->getConfigValue( 'UseRandomUsernames' );
		$this->realNameProcessor = $this->getConfigValue( 'RealNameProcessor' );
		if ( !is_callable( $this->realNameProcessor ) ) {
			$this->realNameProcessor = null;
		}
		$this->emailProcessor = $this->getConfigValue( 'EmailProcessor' );
		if ( !is_callable( $this->emailProcessor ) ) {
			$this->emailProcessor = null;
		}
		$this->preferredUsernameProcessor = $this->getConfigValue( 'PreferredUsernameProcessor' );
		if ( !is_callable( $this->preferredUsernameProcessor ) ) {
			$this->preferredUsernameProcessor = null;
		}
		$this->initClient();
	}

	private function initClient() {
		Assert::precondition( $this->getData()->has( 'clientID' ), 'clientID missing from config' );
		Assert::precondition( $this->getData()->has( 'clientsecret' ), 'clientsecret missing from config' );
		Assert::precondition( $this->getData()->has( 'providerURL' ), 'providerURL missing from config' );

		$this->openIDConnectClient->setProviderURL(
			$this->getData()->get( 'providerURL' )
		);

		$this->openIDConnectClient->setIssuer(
			$this->getData()->get( 'providerURL' )
		);

		$this->openIDConnectClient->setClientID(
			$this->getData()->get( 'clientID' )
		);

		$this->openIDConnectClient->setClientSecret(
			$this->getData()->get( 'clientsecret' )
		);

		if ( $this->forceReauth ) {
			$this->openIDConnectClient->addAuthParam( [ 'prompt' => 'login' ] );
		}

		if ( $this->getData()->has( 'authparam' ) && is_array( $this->getData()->get( 'authparam' ) ) ) {
			$this->openIDConnectClient->addAuthParam( $this->getData()->get( 'authparam' ) );
		}

		if ( $this->getData()->has( 'scope' ) ) {
			if ( is_array( $this->getData()->get( 'scope' ) ) ) {
				$scopes = $this->getData()->get( 'scope' );
			} else {
				$scopes = explode( ' ', $this->getData()->get( 'scope' ) );
			}
		} else {
			$scopes = [ 'openid', 'profile', 'email' ];
		}
		$this->openIDConnectClient->addScope( $scopes );

		if ( $this->getData()->has( 'proxy' ) ) {
			$this->openIDConnectClient->setHttpProxy( $this->getData()->get( 'proxy' ) );
		}

		if ( $this->getData()->has( 'verifyHost' ) ) {
			$this->openIDConnectClient->setVerifyHost( $this->getData()->get( 'verifyHost' ) );
		}

		if ( $this->getData()->has( 'verifyPeer' ) ) {
			$this->openIDConnectClient->setVerifyPeer( $this->getData()->get( 'verifyPeer' ) );
		}

		if ( $this->getData()->has( 'providerConfig' ) ) {
			$this->openIDConnectClient->providerConfigParam( $this->getData()->get( 'providerConfig' ) );
		}

		if ( $this->getData()->has( 'issuerValidator' ) ) {
			$issuerValidator = $this->getData()->get( 'issuerValidator' );
			if ( is_callable( $issuerValidator ) ) {
				$this->openIDConnectClient->setIssuerValidator( $issuerValidator );
			}
		}

		if ( $this->getData()->has( 'wellKnownConfigParameters' ) ) {
			$wellKnownConfigParameters = $this->getData()->get( 'wellKnownConfigParameters' );
			if ( is_array( $wellKnownConfigParameters ) ) {
				$this->openIDConnectClient->setWellKnownConfigParameters( $wellKnownConfigParameters );
			}
		}

		if ( $this->getData()->has( 'codeChallengeMethod' ) ) {
			$this->openIDConnectClient->setCodeChallengeMethod(
				$this->getData()->get( 'codeChallengeMethod' )
			);
		}

		if ( $this->getData()->has( 'authMethods' ) ) {
			$authMethods = $this->getData()->get( 'authMethods' );
			if ( is_array( $authMethods ) ) {
				$this->openIDConnectClient->setTokenEndpointAuthMethodsSupported( $authMethods );
			}
		}

		if ( $this->getData()->has( 'privateKeyJwtGenerator' ) ) {
			$privateKeyJwtGenerator = $this->getData()->get( 'privateKeyJwtGenerator' );
			if ( is_callable( $privateKeyJwtGenerator ) ) {
				$this->openIDConnectClient->setPrivateKeyJwtGenerator( $privateKeyJwtGenerator );
			}
		}

		$redirectURL = SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL();
		$this->openIDConnectClient->setRedirectURL( $redirectURL );
		$this->getLogger()->debug( 'Redirect URL: ' . $redirectURL );
	}

	/**
	 * @param string $name
	 * @return mixed
	 */
	private function getConfigValue( string $name ) {
		return $this->getData()->has( $name ) ? $this->getData()->get( $name ) :
			$this->mainConfig->get( 'OpenIDConnect_' . $name );
	}

	/**
	 * @param int|null &$id The user's user ID
	 * @param string|null &$username The user's username
	 * @param string|null &$realname The user's real name
	 * @param string|null &$email The user's email address
	 * @param string|null &$errorMessage Returns a descriptive message if there's an error
	 * @return bool true if the user has been authenticated and false otherwise
	 * @since 1.0
	 *
	 */
	public function authenticate(
		?int &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		try {
			if ( $this->openIDConnectClient->authenticate() ) {
				$realname = $this->getClaim( 'name' );
				$email = $this->getClaim( 'email' );

				$this->subject = $this->getClaim( 'sub' );
				$this->authManager->setAuthenticationSessionData( self::OIDC_SUBJECT_SESSION_KEY, $this->subject );

				$this->issuer = $this->openIDConnectClient->getProviderURL();
				$this->authManager->setAuthenticationSessionData( self::OIDC_ISSUER_SESSION_KEY, $this->issuer );

				$this->getLogger()->debug(
					'Values retrieved from identity provider are ' .
					'Real name: ' . $realname .
					', Email: ' . $email .
					', Subject: ' . $this->subject .
					', Issuer: ' . $this->issuer
				);

				$accessTokenPayload = (array)$this->openIDConnectClient->getAccessTokenPayload();
				$idTokenPayload = (array)$this->openIDConnectClient->getIdTokenPayload();
				$attributes = array_merge( $idTokenPayload ?: [], $accessTokenPayload ?: [] );
				$this->setSessionSecret(
					self::OIDC_ACCESSTOKENFULL_SESSION_KEY,
					$this->openIDConnectClient->getAccessToken()
				);
				$this->setSessionSecret(
					self::OIDC_ACCESSTOKEN_SESSION_KEY,
					$accessTokenPayload
				);
				$this->setSessionSecret(
					self::OIDC_IDTOKEN_SESSION_KEY,
					$this->openIDConnectClient->getIdToken()
				);
				$this->setSessionSecret(
					self::OIDC_IDTOKENPAYLOAD_SESSION_KEY,
					$idTokenPayload
				);
				$this->setSessionSecret(
					self::OIDC_REFRESHTOKEN_SESSION_KEY,
					$this->openIDConnectClient->getRefreshToken()
				);

				if ( $this->realNameProcessor ) {
					$realname = ( $this->realNameProcessor )( $realname, $attributes );
					$this->getLogger()->debug( 'Real name after processing: ' . $realname );
				}

				if ( $this->emailProcessor ) {
					$email = ( $this->emailProcessor )( $email, $attributes );
					$this->getLogger()->debug( 'Email after processing: ' . $email );
				}

				[ $id, $username ] =
					$this->openIDConnectStore->findUser( $this->subject, $this->issuer );
				if ( $id !== null ) {
					$this->getLogger()->debug( 'Found user with matching subject and issuer' );
					return true;
				}

				$this->getLogger()->debug( 'No user found with matching subject and issuer' );

				if ( $this->migrateUsersByEmail && ( $email ?? '' ) !== '' ) {
					$this->getLogger()->debug( 'Checking for email migration' );
					[ $id, $username, $email ] = $this->getMigratedIdByEmail( $email );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->getLogger()->debug( 'Migrated user ' . $username . ' by email: ' . $email );
						return true;
					}
				}

				$preferred_username = $this->getPreferredUsername( $realname, $email, $attributes );
				$this->getLogger()->debug( 'Preferred username: ' . $preferred_username );

				if ( $this->migrateUsersByUserName ) {
					$this->getLogger()->debug( 'Checking for username migration' );
					$id = $this->getMigratedIdByUserName( $preferred_username );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->getLogger()->debug( 'Migrated user by username: ' . $preferred_username );
						$username = $preferred_username;
						return true;
					}
				}

				if ( $this->useRandomUsernames ) {
					$username = $this->getRandomUsername();
				} else {
					$username = $this->getAvailableUsername( $preferred_username );
				}

				$this->getLogger()->debug( 'Using username: ' . $username );

				return true;
			}

		} catch ( Exception $e ) {
			$this->getLogger()->debug( $e->__toString() );
			$errorMessage = $e->__toString();
			SessionManager::getGlobalSession()->clear();
		}
		return false;
	}

	/**
	 * @param UserIdentity &$user
	 * @since 1.0
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		if ( $this->singleLogout ) {
			$idToken = $this->getSessionSecret( self::OIDC_IDTOKEN_SESSION_KEY );
			$returnTo = $this->authManager->getRequest()->getVal( 'returnto' );
			$title = null;
			if ( $returnTo ) {
				$title = $this->titleFactory->newFromText( $returnTo );
			}
			if ( !$title ) {
				$title = $this->titleFactory->newMainPage();
			}
			$this->openIDConnectClient->signOut( $idToken, $title->getFullURL() );
		}
	}

	/**
	 * @param UserIdentity $user
	 * @return array
	 * @since 7.0
	 */
	public function getAttributes( UserIdentity $user ): array {
		return array_merge(
			$this->getSessionSecret( self::OIDC_IDTOKENPAYLOAD_SESSION_KEY ) ?: [],
			$this->getAccessToken() ?: []
		);
	}

	/**
	 * @param int $id user id
	 * @since 1.0
	 */
	public function saveExtraAttributes( int $id ): void {
		if ( $this->subject === null ) {
			$this->subject = $this->authManager->getAuthenticationSessionData( self::OIDC_SUBJECT_SESSION_KEY );
		}
		if ( $this->issuer === null ) {
			$this->issuer = $this->authManager->getAuthenticationSessionData( self::OIDC_ISSUER_SESSION_KEY );
		}
		$this->openIDConnectStore->saveExtraAttributes( $id, $this->subject, $this->issuer );
	}

	/**
	 * @return bool
	 * @since 7.0
	 */
	public function shouldOverrideDefaultLogout(): bool {
		return $this->singleLogout;
	}

	private function setSessionSecret( $key, $value ) {
		$this->authManager->getRequest()->getSession()->setSecret( $key, $value );
	}

	private function getSessionSecret( $key ) {
		return $this->authManager->getRequest()->getSession()->getSecret( $key );
	}

	private function getPreferredUsername(
		?string $realname,
		?string $email,
		array $attributes
	): ?string {
		if ( $this->getData()->has( 'preferred_username' ) ) {
			$attributeName = $this->getData()->get( 'preferred_username' );
			$this->getLogger()->debug( 'Using ' . $attributeName . ' attribute for preferred username' );
			$preferred_username = $this->getClaim( $attributeName );
		} else {
			$preferred_username = $this->getClaim( 'preferred_username' );
		}

		if ( is_string( $preferred_username ) && strlen( $preferred_username ) > 0 ) {
			$this->getLogger()->debug( 'Preferred username from identity provider: ' . $preferred_username );
			// do nothing
		} elseif ( $this->useRealNameAsUserName && ( $realname ?? '' ) !== '' ) {
			$preferred_username = $realname;
			$this->getLogger()->debug( 'Using real name for preferred username: ' . $preferred_username );
		} elseif ( $this->useEmailNameAsUserName && ( $email ?? '' ) !== '' ) {
			$pos = strpos( $email, '@' );
			if ( $pos !== false && $pos > 0 ) {
				$preferred_username = substr( $email, 0, $pos );
			} else {
				$preferred_username = $email;
			}
			$this->getLogger()->debug( 'Using email for preferred username: ' . $preferred_username );
		} else {
			$preferred_username = null;
			$this->getLogger()->debug( 'No preferred username' );
		}

		if ( $this->preferredUsernameProcessor ) {
			$preferred_username = ( $this->preferredUsernameProcessor )( $preferred_username, $attributes );
			$this->getLogger()->debug( 'Preferred username after processing: ' . $preferred_username );
		}

		if ( !is_string( $preferred_username ) || strlen( $preferred_username ) == 0 ) {
			return null;
		}

		$title = $this->titleFactory->makeTitleSafe( NS_USER, $preferred_username );
		if ( $title === null ) {
			return null;
		}

		return $title->getText();
	}

	private function getMigratedIdByUserName( ?string $username ): ?string {
		$title = $this->titleFactory->makeTitleSafe( NS_USER, $username );
		if ( $title === null ) {
			$this->getLogger()->debug( 'Invalid preferred username for migration: ' . $username );
			return null;
		}
		$username = $title->getText();
		return $this->openIDConnectStore->getMigratedIdByUserName( $username );
	}

	private function getMigratedIdByEmail( string $email ): array {
		$this->getLogger()->debug( 'Matching user to email ' . $email );
		return $this->openIDConnectStore->getMigratedIdByEmail( $email );
	}

	private function getAvailableUsername( ?string $preferred_username ): string {
		if ( $preferred_username === null ) {
			$preferred_username = 'User';
		}

		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username );
		if ( !$userIdentity || !$userIdentity->isRegistered() ) {
			return $preferred_username;
		}

		$count = 1;
		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		while ( $userIdentity && $userIdentity->isRegistered() ) {
			$count++;
			$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		}
		return $preferred_username . $count;
	}

	/**
	 * @return string
	 */
	private function getRandomUsername(): string {
		while ( true ) {
			$username = $this->userNameUtils->getCanonical(
				$this->globalIdGenerator->newUUIDv4(),
				UserNameUtils::RIGOR_CREATABLE
			);
			if ( $username ) {
				$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $username );
				if ( !$userIdentity || !$userIdentity->isRegistered() ) {
					return $username;
				}
			}
		}
	}

	/**
	 * @return array|null
	 */
	public function getAccessToken(): ?array {
		$accessToken = $this->getSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY );
		if ( $this->checkAccessTokenExp( $accessToken ) ) {
			return $accessToken;
		}
		return $this->refreshAccessToken();
	}

	public function getAccessTokenFull(): ?string {
		$accessTokenFull = $this->getSessionSecret( self::OIDC_ACCESSTOKENFULL_SESSION_KEY );
		$accessToken = $this->getSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY );
		if ( $this->checkAccessTokenExp( $accessToken ) ) {
			return $accessTokenFull;
		}
		return $this->refreshAccessToken( false );
	}

	private function checkAccessTokenExp( mixed $accessToken ): bool {
		return $accessToken
			&& isset( $accessToken['exp'] )
			&& ( gettype( $accessToken['exp'] ) === 'integer' )
			&& ( $accessToken['exp'] >= time() - 300 );
	}

	private function refreshAccessToken( bool $returnPayload = true ): ?string {
		$refreshToken = $this->getSessionSecret( self::OIDC_REFRESHTOKEN_SESSION_KEY );
		if ( $refreshToken ) {
			$json = $this->openIDConnectClient->refreshToken( $refreshToken );
			if ( isset( $json->refresh_token ) ) {
				$this->setSessionSecret( self::OIDC_REFRESHTOKEN_SESSION_KEY, $json->refresh_token );
			}
			$accessToken = (array)$this->openIDConnectClient->getAccessTokenPayload();
			$accessTokenFull = $this->openIDConnectClient->getAccessToken();
			$this->setSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY, $accessToken );
			$this->setSessionSecret( self::OIDC_ACCESSTOKENFULL_SESSION_KEY, $accessTokenFull );
			return $returnPayload ? $accessToken : $accessTokenFull;
		}
		return null;
	}

	/**
	 * This function first tries to get a claim from the ID token. If not found it aks the user info endpoint.
	 * The function shall be called from authenticate() only.
	 *
	 * @param string $claimName The name of a claim.
	 * @return string|null The claim value or null
	 */
	private function getClaim( string $claimName ): ?string {
		$value = $this->openIDConnectClient->getVerifiedClaims( $claimName );
		if ( $value ) {
			return $value;
		}
		return $this->openIDConnectClient->requestUserInfo( $claimName );
	}

	/**
	 * @inheritDoc
	 */
	public function canHandle( RequestInterface $request ): bool {
		try {
			// If this plugin can not handle the request
			// (e.g. because there is no `logout_token` at all)
			// then an exception is thrown.
			// The actual validity of the `logout_token` is checked
			// in performBackchannelLogout()
			$this->openIDConnectClient->verifyLogoutToken();
		} catch ( Exception $e ) {
			$this->getLogger()->debug( 'This plugin can not handle the request' );
			$this->getLogger()->debug( $e->getMessage() );
			return false;
		}
		return true;
	}

	/**
	 * @inheritDoc
	 */
	public function performBackchannelLogout(
		RequestInterface $request,
		ResponseInterface $response,
		SessionManagerInterface $sessionManager
	): void {
		$json = [];
		try {
			$oidc = $this->openIDConnectClient;
			if ( $oidc->verifyLogoutToken() ) {
				$subject = $oidc->getSubjectFromBackChannel();
				$issuer = $oidc->getIssuer();
				$this->getLogger()->debug( "'subject' from LogoutToken: $subject" );

				[ $id, $username ] =
					$this->openIDConnectStore->findUser( $subject, $issuer );
				$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $username );
				$user = $this->userFactory->newFromUserIdentity( $userIdentity );

				$this->getLogger()->debug(
					"Logging out: {username} ({userid})",
					[
						'username' => $user->getName(),
						'userid' => $user->getId()
					]
				);
				$sessionManager->invalidateSessionsForUser( $user );

				$response->setStatus( 200 );
			} else {
				$response->setStatus( 400 );
				$this->getLogger()->debug( 'Could not verify logout token' );
				$json = [
					'error' => 'not-verified',
					'error_description' => 'The provided logout token could not be verified'
				];
			}
		} catch ( Exception $ex ) {
			$response->setStatus( 400 );
			$message = $ex->getMessage();
			$this->getLogger()->error( "Exception: $message" );
			$json = [
				'error' => $ex->getCode(),
				'error_description' => $message
			];
		}

		$response->setBody( new StringStream( json_encode( $json ) ) );
	}
}
