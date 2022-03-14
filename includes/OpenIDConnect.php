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

use DatabaseUpdater;
use Exception;
use FakeMaintenance;
use Jumbojett\OpenIDConnectClient;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\SessionManager;
use SpecialPage;
use Title;
use User;

class OpenIDConnect extends PluggableAuth {

	/**
	 * @var AuthManager
	 */
	private $authManager;

	/**
	 * @var OpenIDConnectStore
	 */
	private $openIDConnectStore;

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

	const OIDC_GROUP_PREFIX = 'oidc_';

	/**
	 * @param AuthManager $authManager
	 * @param OpenIDConnectStore $openIDConnectStore
	 */
	public function __construct(
		AuthManager $authManager,
		OpenIDConnectStore $openIDConnectStore
	) {
		$this->authManager = $authManager;
		$this->openIDConnectStore = $openIDConnectStore;
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

		if ( !isset( $GLOBALS['wgOpenIDConnect_Config'] ) ) {
			$this->logger->debug( 'wgOpenIDConnect_Config not set' . PHP_EOL );
			return false;
		}

		try {

			$session = SessionManager::getGlobalSession();

			$iss = $session->get( 'iss' );

			if ( $iss !== null ) {

				if ( isset( $_REQUEST['code'] ) && isset( $_REQUEST['status'] ) ) {
					$session->remove( 'iss' );
				}

				if ( isset( $GLOBALS['wgOpenIDConnect_Config'][$iss] ) ) {

					$config = $GLOBALS['wgOpenIDConnect_Config'][$iss];

					if ( !isset( $config['clientID'] ) ||
						!isset( $config['clientsecret'] ) ) {
						$this->logger->debug( 'clientID or clientsecret not set for ' . $iss . '.' . PHP_EOL );
						$params = [
							'uri' => urlencode( $_SERVER['REQUEST_URI'] ),
							'query' => urlencode( $_SERVER['QUERY_STRING'] )
						];
						self::redirect( 'Special:SelectOpenIDConnectIssuer',
							$params, true );
						return false;
					}

				} else {
					$this->logger->debug( 'Issuer ' . $iss . ' does not exist in wgOpeIDConnect_Config.' . PHP_EOL );
					return false;
				}

			} else {

				$iss_count = count( $GLOBALS['wgOpenIDConnect_Config'] );

				if ( $iss_count < 1 ) {
					return false;
				}

				if ( $iss_count == 1 ) {

					$iss = array_keys( $GLOBALS['wgOpenIDConnect_Config'] );
					$iss = $iss[0];

					$values = array_values( $GLOBALS['wgOpenIDConnect_Config'] );
					$config = $values[0];

					if ( !isset( $config['clientID'] ) ||
						!isset( $config['clientsecret'] ) ) {
						$this->logger->debug( 'clientID or clientsecret not set for ' . $iss . '.' . PHP_EOL );
						return false;
					}

				} else {

					$params = [
						'uri' => urlencode( $_SERVER['REQUEST_URI'] ),
						'query' => urlencode( $_SERVER['QUERY_STRING'] )
					];
					self::redirect( 'Special:SelectOpenIDConnectIssuer',
						$params, true );
					return false;
				}
			}

			$clientID = $config['clientID'];
			$clientsecret = $config['clientsecret'];

			$oidc = new OpenIDConnectClient( $iss, $clientID, $clientsecret );
			if ( isset( $_REQUEST['forcelogin'] ) ) {
				$oidc->addAuthParam( [ 'prompt' => 'login' ] );
			}
			if ( isset( $config['authparam'] ) &&
				is_array( $config['authparam'] ) ) {
				$oidc->addAuthParam( $config['authparam'] );
			}
			if ( isset( $config['scope'] ) ) {
				$scope = $config['scope'];
				if ( is_array( $scope ) ) {
					foreach ( $scope as $s ) {
						$oidc->addScope( $s );
					}
				} else {
					$oidc->addScope( $scope );
				}
			}
			if ( isset( $config['proxy'] ) ) {
				$oidc->setHttpProxy( $config['proxy'] );
			}
			if ( isset( $config['verifyHost'] ) ) {
				$oidc->setVerifyHost( $config['verifyHost'] );
			}
			if ( isset( $config['verifyPeer'] ) ) {
				$oidc->setVerifyPeer( $config['verifyPeer'] );
			}
			if ( isset( $config['providerConfig'] ) ) {
				$oidc->providerConfigParam( $config['providerConfig'] );
			}
			$redirectURL =
				SpecialPage::getTitleFor( 'PluggableAuthLogin' )->getFullURL();
			$oidc->setRedirectURL( $redirectURL );
			$this->logger->debug( 'Redirect URL: ' . $redirectURL );
			if ( $oidc->authenticate() ) {

				$realname = $oidc->requestUserInfo( 'name' );
				$email = $oidc->requestUserInfo( 'email' );
				$this->subject = $oidc->requestUserInfo( 'sub' );
				$this->issuer = $oidc->getProviderURL();
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

				if ( $GLOBALS['wgOpenIDConnect_MigrateUsersByEmail'] === true ) {
					$this->logger->debug( 'Checking for email migration.' . PHP_EOL );
					list( $id, $username ) = $this->getMigratedIdByEmail( $email );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->logger->debug( 'Migrated user ' . $username . ' by email: ' . $email . '.' . PHP_EOL );
						return true;
					}
				}

				$preferred_username = $this->getPreferredUsername( $config, $oidc,
					$realname, $email );
				$this->logger->debug( 'Preferred username: ' . $preferred_username . PHP_EOL );

				if ( $GLOBALS['wgOpenIDConnect_MigrateUsersByUserName'] === true ) {
					$this->logger->debug( 'Checking for username migration.' . PHP_EOL );
					$id = $this->getMigratedIdByUserName( $preferred_username );
					if ( $id !== null ) {
						$this->saveExtraAttributes( $id );
						$this->logger->debug( 'Migrated user by username: ' . $preferred_username . '.' . PHP_EOL );
						$username = $preferred_username;
						return true;
					}
				}

				$username = self::getAvailableUsername( $preferred_username );

				$this->logger->debug( 'Available username: ' . $username . PHP_EOL );

				$this->authManager->setAuthenticationSessionData(
					self::OIDC_SUBJECT_SESSION_KEY, $this->subject );
				$this->authManager->setAuthenticationSessionData(
					self::OIDC_ISSUER_SESSION_KEY, $this->issuer );
				return true;
			}

		} catch ( Exception $e ) {
			$this->logger->debug( $e->__toString() . PHP_EOL );
			$errorMessage = $e->__toString();
			$session->clear();
		}
		return false;
	}

	/**
	 * @since 1.0
	 *
	 * @param User &$user
	 */
	public function deauthenticate( User &$user ): void {
		if ( $GLOBALS['wgOpenIDConnect_ForceLogout'] === true ) {
			$returnto = 'Special:UserLogin';
			$params = [ 'forcelogin' => 'true' ];
			self::redirect( $returnto, $params );
		}
	}

	/**
	 * @since 1.0
	 *
	 * @param int $id user id
	 */
	public function saveExtraAttributes( $id ): void {
		if ( $this->subject === null ) {
			$this->subject = $this->authManager->getAuthenticationSessionData(
				self::OIDC_SUBJECT_SESSION_KEY );
			$this->authManager->removeAuthenticationSessionData(
				self::OIDC_SUBJECT_SESSION_KEY );
		}
		if ( $this->issuer === null ) {
			$this->issuer = $this->authManager->getAuthenticationSessionData(
				self::OIDC_ISSUER_SESSION_KEY );
			$this->authManager->removeAuthenticationSessionData(
				self::OIDC_ISSUER_SESSION_KEY );
		}
		$this->openIDConnectStore->saveExtraAttributes( $id, $this->subject, $this->issuer );
	}

	/**
	 * Will populate the groups for this user with configurable properties from the access token,
	 * if one is available for the user.
	 * Groups will be prefixed with 'oidc_' so the plugin is able to remove them if necessary, i.e.
	 * when a different access token is used at some other time that contains different groups.
	 *
	 * @param User $user
	 */
	public static function populateGroups( User $user ) {
		$old_oidc_groups = array_unique( array_filter( $user->getGroups(), static function ( $group ) {
			return strpos( $group, self::OIDC_GROUP_PREFIX ) === 0;
		} ) );
		$new_oidc_groups = self::getOIDCGroups( $user );
		foreach ( array_diff( $old_oidc_groups, $new_oidc_groups ) as $group_to_remove ) {
			$user->removeGroup( $group_to_remove );
		}
		foreach ( array_diff( $new_oidc_groups, $old_oidc_groups ) as $group_to_add ) {
			$user->addGroup( $group_to_add );
		}
	}

	private static function getOIDCGroups( User $user ) {
		$accessToken = self::getAccessToken( $user );
		if ( $accessToken === null ) {
			wfDebugLog( 'OpenID Connect', 'No token found for user' . PHP_EOL );
			return [];
		}
		$config = self::issuerConfig( $accessToken->iss );
		if ( $config === null ) {
			wfDebugLog( 'OpenID Connect', "No config found for issuer '$accessToken->iss'" . PHP_EOL );
			return [];
		}
		$new_oidc_groups = [];
		foreach ( [ 'global_roles', 'wiki_roles' ] as $role_config ) {
			$roleProperty = self::getNestedPropertyAsArray( $config, [ $role_config, 'property' ] );
			if ( empty( $roleProperty ) ) {
				continue;
			}
			$intermediatePrefixes = ( self::getNestedPropertyAsArray( $config, [ $role_config, 'prefix' ] )
				?: [ '' ] );
			foreach ( self::getNestedPropertyAsArray( $accessToken, $roleProperty ) as $role ) {
				foreach ( $intermediatePrefixes as $prefix ) {
					$new_oidc_groups[] = self::OIDC_GROUP_PREFIX . $prefix . $role;
				}
			}
		}
		$new_oidc_groups = array_unique( $new_oidc_groups );
		return $new_oidc_groups;
	}

	private static function getNestedPropertyAsArray( $obj, array $properties ) {
		if ( $obj === null ) {
			return [];
		}
		while ( !empty( $properties ) ) {
			$property = array_shift( $properties );
			if ( is_array( $obj ) ) {
				if ( !array_key_exists( $property, $obj ) ) {
					return [];
				}
				$obj = $obj[$property];
			} else {
				if ( !property_exists( $obj, $property ) ) {
					return [];
				}
				$obj = $obj->$property;
			}
		}
		return is_array( $obj ) ? $obj : [ $obj ];
	}

	private static function issuerConfig( $iss ) {
		return isset( $GLOBALS['wgOpenIDConnect_Config'][$iss] )
			? $GLOBALS['wgOpenIDConnect_Config'][$iss]
			: null;
	}

	private static function getAccessToken( User $user ) {
		$accessToken = MediaWikiServices::getInstance()->getAuthManager()
			->getAuthenticationSessionData( self::OIDC_ACCESSTOKEN_SESSION_KEY );
		if ( $accessToken === null ) {
			return null;
		}
		$store = MediaWikiServices::getInstance()->get( 'OpenIDConnectStore' );
		list( $userId ) = $store->findUser( $accessToken->sub, $accessToken->iss );
		if ( $userId != $user->getId() ) {
			return null;
		}
		return $accessToken;
	}

	private static function getPreferredUsername( $config, $oidc, $realname,
		$email ) {
		if ( isset( $config['preferred_username'] ) ) {
			wfDebugLog( 'OpenID Connect', 'Using ' . $config['preferred_username'] .
				' attribute for preferred username.' . PHP_EOL );
			$preferred_username =
				$oidc->requestUserInfo( $config['preferred_username'] );
		} else {
			$preferred_username = $oidc->requestUserInfo( 'preferred_username' );
		}
		if ( strlen( $preferred_username ) > 0 ) {
			// do nothing
		} elseif ( strlen( $realname ) > 0 &&
			$GLOBALS['wgOpenIDConnect_UseRealNameAsUserName'] === true ) {
			$preferred_username = $realname;
		} elseif ( strlen( $email ) > 0 &&
			$GLOBALS['wgOpenIDConnect_UseEmailNameAsUserName'] === true ) {
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

	private function getMigratedIdByUserName( $username ) {
		$nt = Title::makeTitleSafe( NS_USER, $username );
		if ( $nt === null ) {
			$this->logger->debug( 'Invalid preferred username for migration: ' . $username . '.' . PHP_EOL );
			return null;
		}
		$username = $nt->getText();
		return $this->openIDConnectStore->getMigratedIdByUserName( $username );
	}

	private function getMigratedIdByEmail( $email ) {
		$this->logger->debug( 'Matching user to email ' . $email . '.' . PHP_EOL );
		return $this->openIDConnectStore->getMigratedIdByEmail( $email );
	}

	private static function getAvailableUsername( $preferred_username ) {
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

	private static function redirect( $page, $params = [], $doExit = false ) {
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

	/**
	 * Implements LoadExtensionSchemaUpdates hook.
	 *
	 * @param DatabaseUpdater $updater
	 */
	public static function loadExtensionSchemaUpdates( $updater ) {
		$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
		$type = $updater->getDB()->getType();
		$updater->addExtensionTable( 'openid_connect',
			$dir . $type . '/AddTable.sql' );
		$updater->addExtensionUpdate( [ [ __CLASS__, 'migrateSubjectAndIssuer' ],
			$updater ] );
	}

	/**
	 * Migrate subject and issuer columns from user table to openid_connect
	 * table.
	 *
	 * @param DatabaseUpdater $updater
	 */
	public static function migrateSubjectAndIssuer( $updater ) {
		if ( $updater->getDB()->fieldExists( 'user', 'subject', __METHOD__ ) &&
			$updater->getDB()->fieldExists( 'user', 'issuer', __METHOD__ ) ) {
			$maintenance = new FakeMaintenance();
			$task = $maintenance->runChild(
				'MigrateOIDCSubjectAndIssuerFromUserTable' );
			if ( $task->execute() ) {
				$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
				$type = $updater->getDB()->getType();
				$patch = $dir . $type . '/DropColumnsFromUserTable.sql';
				$updater->modifyExtensionField( 'user', 'subject', $patch );
			}
		} else {
			$updater->output(
				'...user table does not have subject and issuer columns.' . PHP_EOL );
		}
	}
}
