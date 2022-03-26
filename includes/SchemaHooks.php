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
use FakeMaintenance;
use MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook;

class SchemaHooks implements LoadExtensionSchemaUpdatesHook {
	/**
	 * Updates database schema.
	 *
	 * @param DatabaseUpdater $updater database updater
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
		$type = $updater->getDB()->getType();
		$updater->addExtensionTable( 'openid_connect', $dir . $type . '/AddTable.sql' );
		$updater->addExtensionUpdate( [ [ __CLASS__, 'migrateSubjectAndIssuer' ], $updater ] );
	}

	/**
	 * Migrate subject and issuer columns from user table to openid_connect
	 * table.
	 *
	 * @param DatabaseUpdater $updater
	 */
	public static function migrateSubjectAndIssuer( DatabaseUpdater $updater ): void {
		if ( $updater->getDB()->fieldExists( 'user', 'subject', __METHOD__ ) &&
			$updater->getDB()->fieldExists( 'user', 'issuer', __METHOD__ ) ) {
			$maintenance = new FakeMaintenance();
			$task = $maintenance->runChild( 'MigrateOIDCSubjectAndIssuerFromUserTable' );
			if ( $task->execute() ) {
				$dir = $GLOBALS['wgExtensionDirectory'] . '/OpenIDConnect/sql/';
				$type = $updater->getDB()->getType();
				$patch = $dir . $type . '/DropColumnsFromUserTable.sql';
				$updater->modifyExtensionField( 'user', 'subject', $patch );
			}
		} else {
			$updater->output( '...user table does not have subject and issuer columns.' . PHP_EOL );
		}
	}
}
