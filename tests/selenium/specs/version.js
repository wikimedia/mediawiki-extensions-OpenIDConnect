'use strict';

const VersionPage = require( '../pageobjects/version.page' );

describe( 'OpenIDConnect', () => {

	it( 'is configured correctly', async () => {
		await VersionPage.open();

		await expect( await VersionPage.oidcVersion ).toExist();
		await expect( await VersionPage.paVersion ).toExist();

	} );

} );
