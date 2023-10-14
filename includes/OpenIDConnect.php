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
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\Session\SessionManager;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserIdentityLookup;
use SpecialPage;
use Title;
use TitleFactory;
use Wikimedia\Assert\Assert;

class OpenIDConnect extends PluggableAuth {

	/**
	 * @var Config
	 */
	private $mainConfig;

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var UserIdentityLookup
	 */
	private $userIdentityLookup;

	/**
	 * @var OpenIDConnectStore
	 */
	private $openIDConnectStore;

	/**
	 * @var TitleFactory
	 */
	private $titleFactory;

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
	const OIDC_IDTOKEN_SESSION_KEY = 'OpenIDConnectIdToken';
	const OIDC_IDTOKENPAYLOAD_SESSION_KEY = 'OpenIDConnectIdTokenPayload';
	const OIDC_REFRESHTOKEN_SESSION_KEY = 'OpenIDConnectRefreshToken';

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param UserIdentityLookup $userIdentityLookup
	 * @param OpenIDConnectStore $openIDConnectStore
	 * @param TitleFactory $titleFactory
	 */
	public function __construct(
		Config $mainConfig,
		AuthManager $authManager,
		UserIdentityLookup $userIdentityLookup,
		OpenIDConnectStore $openIDConnectStore,
		TitleFactory $titleFactory
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->userIdentityLookup = $userIdentityLookup;
		$this->openIDConnectStore = $openIDConnectStore;
		$this->titleFactory = $titleFactory;
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
		if ( !array_key_exists( 'SERVER_PORT', $_SERVER ) ) {
			$this->getLogger()->debug( 'in authenticate, server port not set' . PHP_EOL );
			return false;
		}

		try {
			$oidc = $this->getClient();

			if ( $this->forceReauth ) {
				$oidc->addAuthParam( [ 'prompt' => 'login' ] );
			}

			if ( $this->getData()->has( 'authparam' ) && is_array( $this->getData()->get( 'authparam' ) ) ) {
				$oidc->addAuthParam( $this->getData()->get( 'authparam' ) );
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
			foreach ( $scopes as $scope ) {
				$oidc->addScope( $scope );
			}

			if ( $this->getData()->has( 'proxy' ) ) {
				$oidc->setHttpProxy( $this->getData()->get( 'proxy' ) );
			}

			if ( $this->getData()->has( 'verifyHost' ) ) {
				$oidc->setVerifyHost( $this->getData()->get( 'verifyHost' ) );
			}

			if ( $this->getData()->has( 'verifyPeer' ) ) {
				$oidc->setVerifyPeer( $this->getData()->get( 'verifyPeer' ) );
			}

			if ( $this->getData()->has( 'providerConfig' ) ) {
				$oidc->providerConfigParam( $this->getData()->get( 'providerConfig' ) );
			}

			$redirectURL = SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL();
			$oidc->setRedirectURL( $redirectURL );
			$this->getLogger()->debug( 'Redirect URL: ' . $redirectURL );

			if ( $oidc->authenticate() ) {
				$realname = $this->getClaim( $oidc, 'name' );
				$email = $this->getClaim( $oidc, 'email' );

				$this->subject = $this->getClaim( $oidc, 'sub' );
				$this->authManager->setAuthenticationSessionData( self::OIDC_SUBJECT_SESSION_KEY, $this->subject );

				$this->issuer = $oidc->getProviderURL();
				$this->authManager->setAuthenticationSessionData( self::OIDC_ISSUER_SESSION_KEY, $this->issuer );

				$this->getLogger()->debug(
					'Real name: ' . $realname .
					', Email: ' . $email .
					', Subject: ' . $this->subject .
					', Issuer: ' . $this->issuer
				);

				$this->setSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY, (array)$oidc->getAccessTokenPayload() );
				$this->setSessionSecret( self::OIDC_IDTOKEN_SESSION_KEY, $oidc->getIdToken() );
				$this->setSessionSecret( self::OIDC_IDTOKENPAYLOAD_SESSION_KEY, (array)$oidc->getIdTokenPayload() );
				$this->setSessionSecret( self::OIDC_REFRESHTOKEN_SESSION_KEY, $oidc->getRefreshToken() );

				list( $id, $username ) =
					$this->openIDConnectStore->findUser( $this->subject, $this->issuer );
				if ( $id !== null ) {
					$this->getLogger()->debug( 'Found user with matching subject and issuer.' . PHP_EOL );
					return true;
				}

				$this->getLogger()->debug( 'No user found with matching subject and issuer.' . PHP_EOL );

				if ( $this->migrateUsersByEmail && ( $email ?? '' ) !== '' ) {
					$this->getLogger()->debug( 'Checking for email migration.' . PHP_EOL );
					list( $id, $username ) = $this->getMigratedIdByEmail( $email );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->getLogger()->debug( 'Migrated user ' . $username . ' by email: ' . $email . '.' .
							PHP_EOL );
						return true;
					}
				}

				$preferred_username = $this->getPreferredUsername( $oidc, $realname, $email );
				$this->getLogger()->debug( 'Preferred username: ' . $preferred_username . PHP_EOL );

				if ( $this->migrateUsersByUserName ) {
					$this->getLogger()->debug( 'Checking for username migration.' . PHP_EOL );
					$id = $this->getMigratedIdByUserName( $preferred_username );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->getLogger()->debug( 'Migrated user by username: ' . $preferred_username . '.' .
							PHP_EOL );
						$username = $preferred_username;
						return true;
					}
				}

				$username = $this->getAvailableUsername( $preferred_username );

				$this->getLogger()->debug( 'Available username: ' . $username . PHP_EOL );

				return true;
			}

		} catch ( Exception $e ) {
			$this->getLogger()->debug( $e->__toString() . PHP_EOL );
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
			$oidc = $this->getClient();
			$oidc->signOut( $idToken, $title->getFullURL() );
		}
	}

	/**
	 * @param UserIdentity $user
	 * @return array
	 * @since 7.0
	 */
	public function getAttributes( UserIdentity $user ): array {
		return array_merge(
			$this->getSessionSecret( self::OIDC_IDTOKENPAYLOAD_SESSION_KEY ),
			$this->getAccessToken()
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

	private function getClient(): OpenIDConnectClient {
		Assert::precondition( $this->getData()->has( 'clientID' ), 'clientID missing from config' );
		Assert::precondition( $this->getData()->has( 'clientsecret' ), 'clientsecret missing from config' );
		Assert::precondition( $this->getData()->has( 'providerURL' ), 'providerURL missing from config' );

		return new OpenIDConnectClient(
			$this->getData()->get( 'providerURL' ),
			$this->getData()->get( 'clientID' ),
			$this->getData()->get( 'clientsecret' )
		);
	}

	private function setSessionSecret( $key, $value ) {
		$this->authManager->getRequest()->getSession()->setSecret( $key, $value );
	}

	private function getSessionSecret( $key ) {
		return $this->authManager->getRequest()->getSession()->getSecret( $key );
	}

	private function getPreferredUsername( OpenIDConnectClient $oidc, ?string $realname, ?string $email ): ?string {
		if ( $this->getData()->has( 'preferred_username' ) ) {
			$attributeName = $this->getData()->get( 'preferred_username' );
			$this->getLogger()->debug( 'Using ' . $attributeName . ' attribute for preferred username.' . PHP_EOL );
			$preferred_username = $this->getClaim( $oidc, $attributeName );
		} else {
			$preferred_username = $this->getClaim( $oidc, 'preferred_username' );
		}
		if ( is_string( $preferred_username ) && strlen( $preferred_username ) > 0 ) {
			// do nothing
		} elseif ( $this->useRealNameAsUserName && ( $realname ?? '' ) !== '' ) {
			$preferred_username = $realname;
		} elseif ( $this->useEmailNameAsUserName && ( $email ?? '' ) !== '' ) {
			$pos = strpos( $email, '@' );
			if ( $pos !== false && $pos > 0 ) {
				$preferred_username = substr( $email, 0, $pos );
			} else {
				$preferred_username = $email;
			}
		} else {
			return null;
		}
		$nt = Title::makeTitleSafe( NS_USER, $preferred_username );
		if ( $nt === null ) {
			return null;
		}
		return $nt->getText();
	}

	private function getMigratedIdByUserName( string $username ): ?string {
		$nt = Title::makeTitleSafe( NS_USER, $username );
		if ( $nt === null ) {
			$this->getLogger()->debug( 'Invalid preferred username for migration: ' . $username . '.' . PHP_EOL );
			return null;
		}
		$username = $nt->getText();
		return $this->openIDConnectStore->getMigratedIdByUserName( $username );
	}

	private function getMigratedIdByEmail( string $email ): array {
		$this->getLogger()->debug( 'Matching user to email ' . $email . '.' . PHP_EOL );
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
	 * @return array|null
	 */
	public function getAccessToken(): ?array {
		$accessToken = $this->getSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY );
		if ( $accessToken && isset( $accessToken['exp'] ) && ( gettype( $accessToken['exp'] ) === 'integer' ) &&
			( $accessToken['exp'] >= time() - 300 ) ) {
			return $accessToken;
		}
		$refreshToken = $this->getSessionSecret( self::OIDC_REFRESHTOKEN_SESSION_KEY );
		if ( $refreshToken ) {
			$client = $this->getClient();
			$json = $client->refreshToken( $refreshToken );
			if ( isset( $json->refresh_token ) ) {
				$this->setSessionSecret( self::OIDC_REFRESHTOKEN_SESSION_KEY, $json->refresh_token );
			}
			$accessToken = (array)$client->getAccessTokenPayload();
			$this->setSessionSecret( self::OIDC_ACCESSTOKEN_SESSION_KEY, $accessToken );
			return $accessToken;
		}
		return null;
	}

	/**
	 * This function first tries to get a claim from the ID token. If not found it aks the user info endpoint.
	 * The function shall be called from authenticate() only.
	 *
	 * @param OpenIDConnectClient $oidc OIDC client. Must be the same that was used to authenticate.
	 * @param string $claimName The name of a claim.
	 * @return string|null The claim value or null
	 */
	private function getClaim( $oidc, string $claimName ): ?string {
		$value = $oidc->getVerifiedClaims( $claimName );
		if ( $value ) {
			return $value;
		}
		return $oidc->requestUserInfo( $claimName );
	}
}
