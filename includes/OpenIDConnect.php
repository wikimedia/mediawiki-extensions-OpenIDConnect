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

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param UserIdentityLookup $userIdentityLookup
	 * @param OpenIDConnectStore $openIDConnectStore
	 */
	public function __construct(
		Config $mainConfig,
		AuthManager $authManager,
		UserIdentityLookup $userIdentityLookup,
		OpenIDConnectStore $openIDConnectStore
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->userIdentityLookup = $userIdentityLookup;
		$this->openIDConnectStore = $openIDConnectStore;
	}

	/**
	 * @param string $configId
	 * @param array|null $data
	 * @return void
	 */
	public function init( string $configId, ?array $data ): void {
		parent::init( $configId, $data );
		Assert::precondition( $data !== null, 'data missing from config' );
		$this->migrateUsersByEmail = $this->getConfigValue( 'MigrateUsersByEmail' );
		$this->migrateUsersByUserName = $this->getConfigValue( 'MigrateUsersByUserName' );
		$this->forceReauth = $this->getConfigValue( 'ForceReauth' );
		$this->useRealNameAsUserName = $this->getConfigValue( 'UseRealNameAsUserName' );
		$this->useEmailNameAsUserName = $this->getConfigValue( 'UseEmailNameAsUserName' );
	}

	/**
	 * @param string $name
	 * @return mixed
	 */
	private function getConfigValue( string $name ) {
		return $this->config->has( $name ) ? $this->config->get( $name ) :
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
			$this->logger->debug( 'in authenticate, server port not set' . PHP_EOL );
			return false;
		}

		try {
			if ( !$this->config->has( 'clientID' ) ||
				!$this->config->has( 'clientsecret' ) ||
				!$this->config->has( 'providerURL' ) ) {
				$this->logger->debug( 'clientID, clientsecret, or providerURL not set' . PHP_EOL );
				return false;
			}

			$oidc = new OpenIDConnectClient(
				$this->config->get( 'providerURL' ),
				$this->config->get( 'clientID' ),
				$this->config->get( 'clientsecret' )
			);

			if ( $this->forceReauth ) {
				$oidc->addAuthParam( [ 'prompt' => 'login' ] );
			}

			if ( $this->config->has( 'authparam' ) && is_array( $this->config->get( 'authparam' ) ) ) {
				$oidc->addAuthParam( $this->config->get( 'authparam' ) );
			}

			if ( $this->config->has( 'scope' ) ) {
				if ( is_array( $this->config->get( 'scope' ) ) ) {
					$scopes = $this->config->get( 'scope' );
				} else {
					$scopes = explode( ' ', $this->config->get( 'scope' ) );
				}
			} else {
				$scopes = [ 'openid', 'profile', 'email' ];
			}
			foreach ( $scopes as $scope ) {
				$oidc->addScope( $scope );
			}

			if ( $this->config->has( 'proxy' ) ) {
				$oidc->setHttpProxy( $this->config->get( 'proxy' ) );
			}

			if ( $this->config->has( 'verifyHost' ) ) {
				$oidc->setVerifyHost( $this->config->get( 'verifyHost' ) );
			}

			if ( $this->config->has( 'verifyPeer' ) ) {
				$oidc->setVerifyPeer( $this->config->get( 'verifyPeer' ) );
			}

			if ( $this->config->has( 'providerConfig' ) ) {
				$oidc->providerConfigParam( $this->config->get( 'providerConfig' ) );
			}

			$redirectURL = SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL();
			$oidc->setRedirectURL( $redirectURL );
			$this->logger->debug( 'Redirect URL: ' . $redirectURL );

			if ( $oidc->authenticate() ) {
				$realname = $oidc->requestUserInfo( 'name' );
				$email = $oidc->requestUserInfo( 'email' );

				$this->subject = $oidc->requestUserInfo( 'sub' );
				$this->authManager->setAuthenticationSessionData( self::OIDC_SUBJECT_SESSION_KEY, $this->subject );

				$this->issuer = $oidc->getProviderURL();
				$this->authManager->setAuthenticationSessionData( self::OIDC_ISSUER_SESSION_KEY, $this->issuer );

				$this->logger->debug(
					'Real name: ' . $realname .
					', Email: ' . $email .
					', Subject: ' . $this->subject .
					', Issuer: ' . $this->issuer
				);

				$this->authManager->setAuthenticationSessionData(
					self::OIDC_ACCESSTOKEN_SESSION_KEY,
					$oidc->getAccessTokenPayload()
				);

				list( $id, $username ) =
					$this->openIDConnectStore->findUser( $this->subject, $this->issuer );
				if ( $id !== null ) {
					$this->logger->debug( 'Found user with matching subject and issuer.' . PHP_EOL );
					return true;
				}

				$this->logger->debug( 'No user found with matching subject and issuer.' . PHP_EOL );

				if ( $this->migrateUsersByEmail && ( $email ?? '' ) !== '' ) {
					$this->logger->debug( 'Checking for email migration.' . PHP_EOL );
					list( $id, $username ) = $this->getMigratedIdByEmail( $email );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->logger->debug( 'Migrated user ' . $username . ' by email: ' . $email . '.' . PHP_EOL );
						return true;
					}
				}

				$preferred_username = $this->getPreferredUsername( $oidc, $realname, $email );
				$this->logger->debug( 'Preferred username: ' . $preferred_username . PHP_EOL );

				if ( $this->migrateUsersByUserName ) {
					$this->logger->debug( 'Checking for username migration.' . PHP_EOL );
					$id = $this->getMigratedIdByUserName( $preferred_username );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->logger->debug( 'Migrated user by username: ' . $preferred_username . '.' . PHP_EOL );
						$username = $preferred_username;
						return true;
					}
				}

				$username = $this->getAvailableUsername( $preferred_username );

				$this->logger->debug( 'Available username: ' . $username . PHP_EOL );

				return true;
			}

		} catch ( Exception $e ) {
			$this->logger->debug( $e->__toString() . PHP_EOL );
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

	private function getPreferredUsername( OpenIDConnectClient $oidc, ?string $realname, ?string $email ): ?string {
		if ( $this->config->has( 'preferred_username' ) ) {
			$attributeName = $this->config->get( 'preferred_username' );
			$this->logger->debug( 'Using ' . $attributeName . ' attribute for preferred username.' . PHP_EOL );
			$preferred_username = $oidc->requestUserInfo( $attributeName );
		} else {
			$preferred_username = $oidc->requestUserInfo( 'preferred_username' );
		}
		if ( strlen( $preferred_username ) > 0 ) {
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
			$this->logger->debug( 'Invalid preferred username for migration: ' . $username . '.' . PHP_EOL );
			return null;
		}
		$username = $nt->getText();
		return $this->openIDConnectStore->getMigratedIdByUserName( $username );
	}

	private function getMigratedIdByEmail( string $email ): array {
		$this->logger->debug( 'Matching user to email ' . $email . '.' . PHP_EOL );
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
}
