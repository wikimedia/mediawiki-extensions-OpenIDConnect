import Page from 'wdio-mediawiki/Page';

class VersionPage extends Page {

	get oidcVersion() {
		return $( '#mw-version-ext-other-OpenID_Connect' );
	}

	get paVersion() {
		return $( '#mw-version-ext-other-PluggableAuth' );
	}

	async open() {
		return super.openTitle( 'Special:Version' );
	}
}

export default new VersionPage();
