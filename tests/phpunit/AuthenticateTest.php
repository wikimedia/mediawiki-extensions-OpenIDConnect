<?php

namespace MediaWiki\Extension\OpenIDConnect\Tests;

use Jumbojett\OpenIDConnectClient;
use MediaWiki\Extension\OpenIDConnect\OpenIDConnect;
use MediaWikiIntegrationTestCase;

/**
 * @covers \MediaWiki\Extension\OpenIDConnect\OpenIDConnect::authenticate
 * @group Database
 */
class AuthenticateTest extends MediaWikiIntegrationTestCase {
	public function addDBDataOnce(): void {
		$user = self::getMutableTestUser()->getUser();
		$user->setName( 'John' );
		$user->setRealName( 'John Doe' );
		$user->setEmail( 'john.doe@example.com' );
		$user->saveSettings();
	}

	private function getClient(
		$config,
		$result,
		$preferred_username = null,
		$realname = null,
		$email = null
	) {
		$client = $this->createNoOpMock( OpenIDConnectClient::class, [
			'setProviderURL',
			'setIssuer',
			'setClientID',
			'setClientSecret',
			'addScope',
			'setRedirectURL',
			'authenticate',
			'getVerifiedClaims',
			'requestUserInfo',
			'getProviderURL',
			'getAccessTokenPayload',
			'getIdToken',
			'getIdTokenPayload',
			'getRefreshToken'
		] );
		$client->method( 'authenticate' )->willReturn( $result );
		$client->method( 'getVerifiedClaims' )->willReturnCallback( static function ( $key ) use ( $realname, $email ) {
			switch ( $key ) {
				case 'name':
					return $realname;
				case 'email':
					return $email;
				case 'sub':
					return $realname;
			}
		} );
		$client->method( 'requestUserInfo' )->willReturnCallback( static function ( $key ) use ( $preferred_username ) {
			switch ( $key ) {
				case 'preferred_username':
					return $preferred_username;
			}
		} );
		$client->method( 'getProviderURL' )->willReturn( $config['data']['providerURL'] );
		$client->method( 'getAccessTokenPayload' )->willReturn( [] );
		$client->method( 'getIdTokenPayload' )->willReturn( [] );
		return $client;
	}

	/**
	 * There are no entries in the openid_connect table for this test, so there will
	 * be no matches of existing users unless migration occurs.
	 *
	 * @dataProvider provideAuthenticateSuccess
	 */
	public function testAuthenticateSuccess(
		$testName,
		$config,
		$preferred_username,
		$realname,
		$email,
		$getIdFromTestUser,
		$expectedUsername,
		$expectedRealname,
		$expectedEmail
	) {
		$client = $this->getClient( $config, true, $preferred_username, $realname, $email );

		$services = $this->getServiceContainer();
		$userIdentityLookup = $services->getUserIdentityLookup();
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$userIdentityLookup,
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );

		$this->assertTrue( $result, $testName . ' result' );
		$expectedId = $getIdFromTestUser ? $userIdentityLookup->getUserIdentityByName( 'John' )->getId() : 0;
		$this->assertEquals( $expectedId, $id, $testName . ' id' );
		$this->assertEquals( $expectedUsername, $username, $testName . ' username' );
		$this->assertEquals( $expectedRealname, $realname, $testName . ' real name' );
		$this->assertEquals( $expectedEmail, $email, $testName . ' email' );
	}

	public function provideAuthenticateSuccess() {
		yield [
			'New user, preferred username, no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue'
				]
			],
			'Jane',
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'Jane',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, preferred username, no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'preferredUsernameProcessor' =>
						fn ( $preferred_username, $attributes ) => strtoupper( $preferred_username ),
					'realnameProcessor' => fn ( $realName, $attributes ) => strtoupper( $realName ),
					'emailProcessor' => fn ( $email, $attributes ) => strtoupper( $email )
				]
			],
			'Jane',
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'JANE',
			'JANE SMITH',
			'JANE.SMITH@EXAMPLE.COM'
		];
		yield [
			'New user, preferred name, user real name as username (ignored), no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'userRealNameAsUsername' => true
				]
			],
			'Jane',
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'Jane',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, preferred name, user real name as username (ignored), no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'userEmailNameAsUsername' => true
				]
			],
			'Jane',
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'Jane',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, no preferred name, user real name as username, no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'useRealNameAsUsername' => true
				]
			],
			null,
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'Jane Smith',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, no preferred name, user real name as username, no conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'useEmailNameAsUsername' => true
				]
			],
			null,
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'Jane.smith',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, no preferred username, no migration',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue'
				]
			],
			null,
			'Jane Smith',
			'jane.smith@example.com',
			false,
			'User',
			'Jane Smith',
			'jane.smith@example.com'
		];
		yield [
			'New user, preferred username, conflict',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue'
				]
			],
			'John',
			'John Doe',
			'john.doe@example.com',
			false,
			'John1',
			'John Doe',
			'john.doe@example.com'
		];
		yield [
			'Migrate by email',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'migrateUsersByEmail' => true
				]
			],
			'John',
			'John Doe',
			'john.doe@example.com',
			true,
			'John',
			'John Doe',
			'john.doe@example.com'
		];
		yield [
			'Migrate by username',
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'migrateUsersByUsername' => true
				]
			],
			'John',
			'John Doe',
			'john.doe@example.com',
			true,
			'John',
			'John Doe',
			'john.doe@example.com'
		];
	}

	public function testAuthenticateFailure() {
		$config =
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
				]
			];
		$client = $this->getClient( $config, false );

		$services = $this->getServiceContainer();
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$services->getUserIdentityLookup(),
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );

		$this->assertFalse( $result, 'authentication failure' );
	}

	public function testAuthenticateRandomUsername() {
		$config =
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
				]
			];
		$client = $this->getClient( $config, true, null, 'Jane Smith', 'jane.smith@example.com' );

		$services = $this->getServiceContainer();
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$services->getUserIdentityLookup(),
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );
		$this->assertTrue( $result, 'authenticate random username first result' );
		$this->assertStringStartsWith( 'User', $username, 'authenticate random username first username' );

		$config['data']['useRandomUsernames'] = true;
		$client = $this->getClient( $config, true, null, 'Julie Jones', 'julie.jones@example.com' );
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$services->getUserIdentityLookup(),
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );
		$this->assertTrue( $result, 'authenticate random username second result' );
		$this->assertStringStartsNotWith( 'User', $username, 'authenticate random username second username' );
	}

	public function testAuthenticateSecondProviderMigration() {
		$config =
			[
				'plugin' => 'OpenIDConnect',
				'data' => [
					'providerURL' => 'https://provider1.url.com',
					'clientID' => 'clientIDvalue',
					'clientsecret' => 'clientsecretvalue',
					'migrateUsersByEmail' => true
				]
			];
		$client = $this->getClient( $config, true, 'John', 'John Doe', 'john.doe@example.com' );

		$services = $this->getServiceContainer();
		$userIdentityLookup = $services->getUserIdentityLookup();
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$userIdentityLookup,
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );
		$existingId = $userIdentityLookup->getUserIdentityByName( 'John' )->getId();
		$oidc->saveExtraAttributes( $existingId );

		$config['data']['providerURL'] = 'https://provider2.url.com';
		$client = $this->getClient( $config, true, 'John', 'John Doe', 'john.doe@example.com' );
		$oidc = new OpenIDConnect(
			$services->getMainConfig(),
			$services->getAuthManager(),
			$client,
			$userIdentityLookup,
			$services->get( 'OpenIDConnectStore' ),
			$services->getTitleFactory(),
			$services->getGlobalIdGenerator()
		);
		$oidc->init( 'configId', $config );
		$result = $oidc->authenticate( $id, $username, $realname, $email, $errorMessage );

		$this->assertTrue( $result, 'authenticate second provider result' );
		// currently this does not match, but when multi-provider support is enabled, it will match
		$this->assertNotEquals( $existingId, $id, 'authenticate second provider id' );
	}
}
