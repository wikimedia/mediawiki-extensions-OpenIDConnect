'use strict';

class Keycloak {

	get kcFormLogin() {
		return $( '#kc-form-login' );
	}

	get usernameField() {
		return $( '#username' );
	}

	get passwordField() {
		return $( '#password' );
	}

	get kcLogin() {
		return $( '#kc-login' );
	}

	async login( username, password ) {
		await this.usernameField.setValue( username );
		await this.passwordField.setValue( password );
		await this.kcLogin.click();
	}
}

module.exports = new Keycloak();
