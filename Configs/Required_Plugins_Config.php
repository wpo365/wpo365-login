<?php

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();
    
    // Load dependencies
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Required_Plugins.php' );

    add_action( 'tgmpa_register', function () {
        
        $plugins = array(
            array(
                'name'      => 'redux-framework',
                'slug'      => 'redux-framework',
                'required'  => true, ) );
            
        $config = array(
            'id'           => 'wpo365',                // Unique ID for hashing notices for multiple instances of TGMPA.
            'default_path' => '',                      // Default absolute path to bundled plugins.
            'menu'         => 'tgmpa-install-plugins', // Menu slug.
            'parent_slug'  => 'plugins.php',           // Parent menu slug.
            'capability'   => 'manage_options',        // Capability needed to view plugin install page, should be a capability associated with the parent menu used.
            'has_notices'  => true,                    // Show admin notices or not.
            'dismissable'  => false,                    // If false, a user cannot dismiss the nag message.
            'dismiss_msg'  => 'Installing redux is required to manage WPO365 options',                      // If 'dismissable' is false, this message will be output at top of nag.
            'is_automatic' => true,                    // Automatically activate plugins after installation or not.
            'message'      => '',                      // Message to output right before the plugins table.
        );

        tgmpa( $plugins, $config );
        
    } );

?>