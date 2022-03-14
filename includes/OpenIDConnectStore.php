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

class OpenIDConnectStore {

	/**
	 * @param int $id user id
	 * @param string $subject
	 * @param string $issuer
	 */
	public function saveExtraAttributes( int $id, string $subject, string $issuer ): void {
		$dbw = wfGetDB( DB_PRIMARY );
		$dbw->upsert(
			'openid_connect',
			[
				'oidc_user' => $id,
				'oidc_subject' => $subject,
				'oidc_issuer' => $issuer
			],
			[
				[ 'oidc_user' ]
			],
			[
				'oidc_subject' => $subject,
				'oidc_issuer' => $issuer
			],
			__METHOD__
		);
	}

	/**
	 * @param string $subject
	 * @param string $issuer
	 * @return array
	 */
	public function findUser( string $subject, string $issuer ): array {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id',
				'user_name'
			],
			[
				'oidc_subject' => $subject,
				'oidc_issuer' => $issuer
			],
			__METHOD__,
			[],
			[
				'openid_connect' => [ 'JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row === false ) {
			return [ null, null ];
		} else {
			return [ $row->user_id, $row->user_name ];
		}
	}

	/**
	 * @param string $username
	 * @return string|null
	 */
	public function getMigratedIdByUserName( string $username ): ?string {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id'
			],
			[
				'user_name' => $username,
				'oidc_user' => null
			],
			__METHOD__,
			[],
			[
				'openid_connect' => [ 'LEFT JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row !== false ) {
			return $row->user_id;
		}
		return null;
	}

	/**
	 * @param string $email
	 * @return array
	 */
	public function getMigratedIdByEmail( string $email ): array {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'openid_connect'
			],
			[
				'user_id',
				'user_name',
				'oidc_user'
			],
			[
				'user_email' => $email
			],
			__METHOD__,
			[
				// if multiple matching accounts, use the oldest one
				'ORDER BY' => 'user_registration'
			],
			[
				'openid_connect' => [ 'LEFT JOIN', [ 'user_id=oidc_user' ] ]
			]
		);
		if ( $row !== false && $row->oidc_user === null ) {
			return [ $row->user_id, $row->user_name ];
		}
		return [ null, null ];
	}
}
