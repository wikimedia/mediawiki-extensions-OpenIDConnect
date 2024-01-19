'use strict';

const MainPage = require( '../pageobjects/main.page' );
const Keycloak = require( '../pageobjects/keycloak' );

describe( 'OpenIDConnect', () => {

	it( 'can login', async () => {
		await MainPage.open();

		const loginLink = await MainPage.loginLink;
		await loginLink.waitForExist();
		await loginLink.waitForClickable();
		await loginLink.click();

		await expect( await Keycloak.usernameField ).toExist();
		await expect( await Keycloak.passwordField ).toExist();
		await expect( await Keycloak.kcLogin ).toExist();

		await Keycloak.login( 'testuser', 'testpass' );

		await expect( await MainPage.userpage ).toExist();
		await expect( await MainPage.userpage ).toHaveText( 'Testuser' );

		await Keycloak.open(
			'admin/master/console/#/test/users/' +
			process.env.TEST_USER_UUID + '/sessions'
		);

		await expect( await Keycloak.usernameField ).toExist();
		await expect( await Keycloak.passwordField ).toExist();
		await expect( await Keycloak.kcLogin ).toExist();

		await Keycloak.login( 'admin', 'admin' );

		await Keycloak.kcLogoutAll.waitForExist( { timeout: 10000 } );
		await Keycloak.kcLogoutAll.click();
		await Keycloak.kcConfirm.click();

		await MainPage.open();

		await browser.waitUntil(
			async () => {
				if ( await MainPage.loginLink.isExisting() ) {
					return true;
				} else {
					await browser.refresh();
					return false;
				}
			},
			{
				timeout: 60000,
				timeoutMsg: 'Login link not found after refreshing.'
			}
		);
	} );
} );
