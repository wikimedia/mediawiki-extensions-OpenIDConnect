import VersionPage from '../pageobjects/version.page.js';

describe( 'OpenIDConnect', () => {

	it( 'is configured correctly', async () => {
		await VersionPage.open();

		await expect( await VersionPage.oidcVersion ).toExist();
		await expect( await VersionPage.paVersion ).toExist();

	} );

} );
