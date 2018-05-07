<?php
/**
 * Migrate subject and issuer columns from the user table to the openid_connect
 * table.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 *
 * @file
 * @ingroup Maintenance
 */

if ( getenv( 'MW_INSTALL_PATH' ) ) {
	require_once getenv( 'MW_INSTALL_PATH' ) . '/maintenance/Maintenance.php';
} else {
	require_once __DIR__ . '/../../../maintenance/Maintenance.php';
}

/**
 * Maintenance script that migrates data in the subject and issuer columns
 * from the user table to the openid_connect table.
 *
 * @ingroup Maintenance
 */
class MigrateOIDCSubjectAndIssuerFromUserTable extends LoggedUpdateMaintenance {
	public function __construct() {
		parent::__construct();
		$this->addDescription( 'Migrates data from user table (for upgrade to 5.X+' );
	}

	/**
	 * @inheritDoc
	 */
	public function getUpdateKey() {
		return __CLASS__;
	}

	/**
	 * @inheritDoc
	 */
	public function doDBUpdates() {
		$dbw = $this->getDB( DB_MASTER );

		if ( !$dbw->fieldExists(
			'user',
			'subject',
			__METHOD__
		 ) ) {
			$this->output( 'No subject column found in user table.' . PHP_EOL );
			return true;
		}

		if ( !$dbw->fieldExists(
			'user',
			'issuer',
			__METHOD__
		 ) ) {
			$this->output( 'No issuer column found in user table.' . PHP_EOL );
			return true;
		}

		$dbw->insertSelect(
			'openid_connect',
			'user',
			[
				'oidc_user' => 'user_id',
				'oidc_subject' => 'subject',
				'oidc_issuer' => 'issuer'
			],
			[
				'subject IS NOT NULL',
				'issuer IS NOT NULL'
			],
			__METHOD__
		);
		$this->output( 'Migrated data from user table to openid_connect table.' .
			PHP_EOL );

		return true;
	}
}

$maintClass = MigrateOIDCSubjectAndIssuerFromUserTable::class;
require_once RUN_MAINTENANCE_IF_MAIN;
