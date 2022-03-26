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
use SpecialPage;
use Title;
use User;
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
	private $forceLogout;

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
	 * @param OpenIDConnectStore $openIDConnectStore
	 */
	public function __construct(
		Config $mainConfig,
		AuthManager $authManager,
		OpenIDConnectStore $openIDConnectStore
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
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
		$this->migrateUsersByEmail =
			$data['migrateUsersByEmail'] ?? $this->mainConfig->get( 'OpenIDConnect_MigrateUsersByEmail' );
		$this->migrateUsersByUserName =
			$data['migrateUsersByUserName'] ?? $this->mainConfig->get( 'OpenIDConnect_MigrateUsersByUserName' );
		$this->forceLogout = $data['forceLogout'] ?? $this->mainConfig->get( 'OpenIDConnect_ForceLogout' );
		$this->useRealNameAsUserName =
			$data['useRealNameAsUserName'] ?? $this->mainConfig->get( 'OpenIDConnect_UseRealNameAsUserName' );
		$this->useEmailNameAsUserName =
			$data['useEmailNameAsUserName'] ?? $this->mainConfig->get( 'OpenIDConnect_UseEmailNameAsUserName' );
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
			if ( !isset( $this->data['clientID'] ) ||
				!isset( $this->data['clientsecret'] ) ||
				!isset( $this->data['providerURL'] ) ) {
				$this->logger->debug( 'clientID, clientsecret, or providerURL not set' . PHP_EOL );
				return false;
			}

			$oidc = new OpenIDConnectClient(
				$this->data['providerURL'],
				$this->data['clientID'],
				$this->data['clientsecret']
			);

			if ( isset( $_REQUEST['forcelogin'] ) ) {
				$oidc->addAuthParam( [ 'prompt' => 'login' ] );
			}

			if ( isset( $this->data['authparam'] ) && is_array( $this->data['authparam'] ) ) {
				$oidc->addAuthParam( $this->data['authparam'] );
			}

			if ( isset( $this->data['scope'] ) ) {
				if ( is_array( $this->data['scope'] ) ) {
					$scopes = $this->data['scope'];
				} else {
					$scopes = explode( ' ', $this->data['scope'] );
				}
			} else {
				$scopes = [ 'openid', 'profile', 'email' ];
			}
			foreach ( $scopes as $scope ) {
				$oidc->addScope( $scope );
			}

			if ( isset( $this->data['proxy'] ) ) {
				$oidc->setHttpProxy( $this->data['proxy'] );
			}

			if ( isset( $this->data['verifyHost'] ) ) {
				$oidc->setVerifyHost( $this->data['verifyHost'] );
			}

			if ( isset( $this->data['verifyPeer'] ) ) {
				$oidc->setVerifyPeer( $this->data['verifyPeer'] );
			}

			if ( isset( $this->data['providerConfig'] ) ) {
				$oidc->providerConfigParam( $this->data['providerConfig'] );
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
	 * @since 1.0
	 *
	 * @param UserIdentity &$user
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		if ( $this->forceLogout ) {
			$returnto = 'Special:UserLogin';
			$params = [ 'forcelogin' => 'true' ];
			$this->redirect( $returnto, $params );
		}
	}

	/**
	 * @since 1.0
	 *
	 * @param int $id user id
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
		if ( isset( $this->data['preferred_username'] ) ) {
			$this->logger->debug( 'Using ' . $this->data['preferred_username'] . ' attribute for preferred username.'
				. PHP_EOL );
			$preferred_username = $oidc->requestUserInfo( $this->data['preferred_username'] );
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

		if ( User::idFromName( $preferred_username ) === null ) {
			return $preferred_username;
		}

		$count = 1;
		while ( User::idFromName( $preferred_username . $count ) !== null ) {
			$count++;
		}
		return $preferred_username . $count;
	}

	private function redirect( string $page, array $params = [], bool $doExit = false ): void {
		$title = Title::newFromText( $page );
		if ( $title === null ) {
			$title = Title::newMainPage();
		}
		$url = $title->getFullURL( $params );
		header( 'Location: ' . $url );
		if ( $doExit ) {
			exit;
		}
	}
}
