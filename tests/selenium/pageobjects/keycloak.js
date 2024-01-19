'use strict';

class Keycloak {

	get usernameField() {
		return $( '#username' );
	}

	get passwordField() {
		return $( '#password' );
	}

	get kcLogin() {
		return $( '#kc-login' );
	}

	get kcLogoutAll() {
		return $( 'button[data-ouia-component-id="OUIA-Generated-Button-primary-1"]' );

	}

	get kcConfirm() {
		return $( '#modal-confirm' );
	}

	async login( username, password ) {
		await this.usernameField.setValue( username );
		await this.passwordField.setValue( password );
		await this.kcLogin.click();
	}

	async open( page ) {
		await browser.url( 'http://' + process.env.HOST_IP + ':8888/' + page );
		await browser.waitUntil(
			() => browser.execute( () => document.readyState === 'complete' ),
			{
				timeout: 10000,
				timeoutMsg: 'Keycloak page did not load in time'
			}
		);
	}
}

module.exports = new Keycloak();
