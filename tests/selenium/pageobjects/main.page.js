import Page from 'wdio-mediawiki/Page';

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

export default new MainPage();
