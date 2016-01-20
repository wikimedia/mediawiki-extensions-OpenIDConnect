<?php

/*
 * Copyright (c) 2015 The MITRE Corporation
 *
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

$wgExtensionFunctions[] = function () {
	if ( !class_exists( 'PluggableAuth' ) ) {
		die( '<b>Error:</b> This extension requires the PluggableAuth extension to be included first' );
	}
};

if ( array_key_exists( 'PluggableAuth_Class', $GLOBALS ) ) {
	die( '<b>Error:</b> A value for $PluggableAuth_Class has already been set.' );
}

$GLOBALS['wgExtensionCredits']['other'][] = array (
	'path' => __FILE__,
	'name' => 'OpenID Connect',
	'version' => '1.2',
	'author' => array(
		'[https://www.mediawiki.org/wiki/User:Cindy.cicalese Cindy Cicalese]'
	),
	'descriptionmsg' => 'openidconnect-desc',
	'url' =>
			'https://www.mediawiki.org/wiki/Extension:OpenID_Connect',
);

$GLOBALS['PluggableAuth_Class'] = 'OpenIDConnect';

$GLOBALS['wgAutoloadClasses']['OpenIDConnect'] =
	__DIR__ . '/OpenIDConnect.class.php';
$GLOBALS['wgAutoloadClasses']['OpenIDConnectClient'] =
	__DIR__ . '/OpenID-Connect-PHP/OpenIDConnectClient.php';

$GLOBALS['wgMessagesDirs']['OpenIDConnect'] = __DIR__ . '/i18n';
$GLOBALS['wgExtensionMessagesFiles']['OpenIDConnect'] =
	__DIR__ . '/OpenIDConnect.i18n.php';

$GLOBALS['wgSpecialPages']['SelectOpenIDConnectIssuer'] =
	'SelectOpenIDConnectIssuer';
$GLOBALS['wgAutoloadClasses']['SelectOpenIDConnectIssuer'] =
	__DIR__ . '/SelectOpenIDConnectIssuer.class.php';
$GLOBALS['wgExtensionMessagesFiles']['SelectOpenIDConnectIssuerAlias'] =
	__DIR__ . '/SelectOpenIDConnectIssuer.alias.php';
$GLOBALS['wgWhitelistRead'][] = "Special:SelectOpenIDConnectIssuer";

$GLOBALS['wgHooks']['LoadExtensionSchemaUpdates'][] =
	'OpenIDConnect::loadExtensionSchemaUpdates';
