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

		await expect( await Keycloak.kcFormLogin ).toExist();
		await expect( await Keycloak.usernameField ).toExist();
		await expect( await Keycloak.passwordField ).toExist();
		await expect( await Keycloak.kcLogin ).toExist();

		await Keycloak.login( 'testuser', 'testpass' );

		await expect( await MainPage.userpage ).toExist();
		await expect( await MainPage.userpage ).toHaveText( 'Testuser' );
	} );

} );
