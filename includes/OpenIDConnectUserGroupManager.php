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

use MediaWiki\Extension\PluggableAuth\PluggableAuthFactory;
use MediaWiki\User\UserGroupManager;
use MediaWiki\User\UserIdentity;
use Psr\Log\LoggerInterface;

class OpenIDConnectUserGroupManager {
	const OIDC_GROUP_PREFIX = 'oidc_';

	/**
	 * @var PluggableAuthFactory
	 */
	private $pluggableAuthFactory;

	/**
	 * @var UserGroupManager
	 */
	private $userGroupManager;

	/**
	 * @var LoggerInterface
	 */
	private $logger;

	/**
	 * @param PluggableAuthFactory $pluggableAuthFactory
	 * @param UserGroupManager $userGroupManager
	 * @param LoggerInterface $logger
	 */
	public function __construct(
		PluggableAuthFactory $pluggableAuthFactory,
		UserGroupManager $userGroupManager,
		LoggerInterface $logger
	) {
		$this->pluggableAuthFactory = $pluggableAuthFactory;
		$this->userGroupManager = $userGroupManager;
		$this->logger = $logger;
	}

	/**
	 * Will populate the groups for this user with configurable properties from the access token,
	 * if one is available for the user.
	 * Groups will be prefixed with 'oidc_' so the plugin is able to remove them if necessary, i.e.
	 * when a different access token is used at some other time that contains different groups.
	 *
	 * @param UserIdentity $user
	 */
	public function populateGroups( UserIdentity $user ) {
		$currentPlugin = $this->pluggableAuthFactory->getInstance();
		if ( !( $currentPlugin instanceof OpenIDConnect ) ) {
			// We can only sync groups in the context of a OpenID Connect authentication flow,
			// not for arbitrary other plugins
			return;
		}
		$accessToken = $currentPlugin->getAccessToken();
		if ( $accessToken === null ) {
			$this->logger->debug( 'No access token found for user' . PHP_EOL );
			return;
		}
		$old_oidc_groups = array_unique( array_filter(
			$this->userGroupManager->getUserGroups( $user ),
			static function ( $group ) {
				return strpos( $group, self::OIDC_GROUP_PREFIX ) === 0;
			}
		) );
		$new_oidc_groups = $this->getOIDCGroups( $user, $accessToken );
		foreach ( array_diff( $old_oidc_groups, $new_oidc_groups ) as $group_to_remove ) {
			$this->userGroupManager->removeUserFromGroup( $user, $group_to_remove );
		}
		foreach ( array_diff( $new_oidc_groups, $old_oidc_groups ) as $group_to_add ) {
			$this->userGroupManager->addUserToGroup( $user, $group_to_add );
		}
	}

	private function getOIDCGroups( UserIdentity $user, $accessToken ): array {
		$config = $this->getIssuerConfig();
		if ( $config === null ) {
			$this->logger->debug( "No config found" . PHP_EOL );
			return [];
		}
		$new_oidc_groups = [];
		foreach ( [ 'global_roles', 'wiki_roles' ] as $role_config ) {
			$roleProperty = $this->getNestedPropertyAsArray( $config, [ $role_config, 'property' ] );
			if ( empty( $roleProperty ) ) {
				continue;
			}
			$intermediatePrefixes = ( $this->getNestedPropertyAsArray( $config, [ $role_config, 'prefix' ] )
				?: [ '' ] );
			foreach ( $this->getNestedPropertyAsArray( $accessToken, $roleProperty ) as $role ) {
				foreach ( $intermediatePrefixes as $prefix ) {
					$new_oidc_groups[] = self::OIDC_GROUP_PREFIX . $prefix . $role;
				}
			}
		}
		return array_unique( $new_oidc_groups );
	}

	private function getNestedPropertyAsArray( $obj, array $properties ): array {
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

	private function getIssuerConfig() {
		$config = $this->pluggableAuthFactory->getCurrentConfig();
		if ( $config ) {
			return $config['data'] ?? null;
		}
		return null;
	}
}
