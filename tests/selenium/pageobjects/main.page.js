'use strict';

const Page = require( 'wdio-mediawiki/Page' );

class MainPage extends Page {

	get loginLink() {
		return $( '#pt-login-2 a' );
	}

	get usernameField() {
		return $( '#username' );
	}

	get passwordField() {
		return $( '#password' );
	}

	get kcFormLogin() {
		return $( '#kc-form-login' );
	}

	get kcLogin() {
		return $( '#kc-login' );
	}

	get userpage() {
		return $( '#pt-userpage-2 span' );
	}

	async open() {
		return super.openTitle( 'Main Page' );
	}

	async login( username, password ) {
		await this.usernameField.setValue( username );
		await this.passwordField.setValue( password );
		await this.kcLogin.click();
	}
}

module.exports = new MainPage();
