'use strict';

const Page = require( 'wdio-mediawiki/Page' );

class MainPage extends Page {

	get loginLink() {
		return $( '#pt-login-2 a' );
	}

	get userpage() {
		return $( '#pt-userpage-2 span' );
	}

	async open() {
		return super.openTitle( 'Main Page' );
	}
}

module.exports = new MainPage();
