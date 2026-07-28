<?php
/**
 * Plugin Name: WP-guard verify
 * Description: Lisää wp-guard-verify-meta-tagin, jolla WP-guard varmistaa että sivusto on omassa ylläpidossa. Kopioi tiedosto kansioon wp-content/mu-plugins/ ja vaihda token alle.
 * Version: 1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Vaihda tähän sama token kuin sites.json:issa tälle sivustolle.
// Multisitessa voi antaa tokenin per sivu blog_id:n mukaan, esim.:
// $tokens = array( 7 => 'token-elava-sivu', 8 => 'token-vanha-sivu' );
// define( 'WP_GUARD_TOKEN', $tokens[ get_current_blog_id() ] ?? '' );
define( 'WP_GUARD_TOKEN', 'VAIHDA-TOKEN-TAHAN' );

add_action( 'wp_head', function () {
	if ( WP_GUARD_TOKEN && 'VAIHDA-TOKEN-TAHAN' !== WP_GUARD_TOKEN ) {
		printf(
			'<meta name="wp-guard-verify" content="%s">' . "\n",
			esc_attr( WP_GUARD_TOKEN )
		);
	}
}, 1 );
