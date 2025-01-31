'use strict';

const MainPage = require( '../pageobjects/main.page' );

describe( 'OpenIDConnect', () => {

	it( 'can login', async () => {
		await MainPage.open();

		await expect( await MainPage.loginLink ).toExist();
		await MainPage.loginLink.waitForClickable();
		await MainPage.loginLink.click();

		await expect( await MainPage.kcFormLogin ).toExist();
		await expect( await MainPage.usernameField ).toExist();
		await expect( await MainPage.passwordField ).toExist();
		await expect( await MainPage.kcLogin ).toExist();

		await MainPage.login( 'testuser', 'testpass' );

		await expect( await MainPage.userpage ).toExist();
		await expect( await MainPage.userpage ).toHaveText( 'Testuser' );

	} );

} );
