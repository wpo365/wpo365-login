<?php

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();
    
    ?>
        <!-- Dependencies -->
        <script crossorigin src="https://unpkg.com/react@16/umd/react.production.min.js"></script>
        <script crossorigin src="https://unpkg.com/react-dom@16/umd/react-dom.production.min.js"></script>

        <!-- Main -->
        <script src="<?php echo $GLOBALS[ 'WPO365_APPS_PLUGIN_URL' ] ?>/apps/dist/wpo365fx.js"
            data-nonce="<?php echo wp_create_nonce( 'wpo365_fx_nonce' ) ?>"
            data-wpajaxadminurl="<?php echo admin_url() . '/admin-ajax.php' ?>"
            data-props="<?php echo htmlspecialchars( $props ) ?>">
        </script>