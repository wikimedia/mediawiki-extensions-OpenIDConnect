'use strict';

const MainPagePage = require( '../pageobjects/mainpage.page' );

describe( 'OpenIDConnect', () => {

	it( 'can login', async () => {
		await MainPagePage.open();

		await expect( await MainPagePage.loginLink ).toExist();
		await MainPagePage.loginLink.waitForClickable();
		await MainPagePage.loginLink.click();
		await expect( await MainPagePage.kcFormLogin ).toExist();
		await expect( await MainPagePage.usernameField ).toExist();
		await expect( await MainPagePage.passwordField ).toExist();
		await expect( await MainPagePage.kcLogin ).toExist();
		await MainPagePage.usernameField.setValue( 'testuser' );
		await MainPagePage.passwordField.setValue( 'testpass' );
		await MainPagePage.kcLogin.click();
		await expect( await MainPagePage.userpage ).toExist();
		await expect( await MainPagePage.userpage ).toHaveText( 'Testuser' );

	} );

} );
