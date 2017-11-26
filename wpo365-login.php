<?php
    /**
     *  Plugin Name: WPO365-login
     *  Plugin URI: https://www.wpo365.com/downloads/wordpress-office-365-login/
     *  Github URI: https://github.com/wpo365/wpo365-login
     *  Description: Wordpress + Office 365 login allows Microsoft O365 users to seamlessly and securely log on to your corporate Wordpress intranet. The plugin will create a Wordpress user for each corporate user when logged on to Office 365 and thus avoiding the default Wordpress login screen: No username or password required.
     *  Version: 2.8
     *  Author: info@wpo365.com
     *  Author URI: https://www.wpo365.com
     *  License: GPL2+
     */
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die( );

    $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] = '2.8';
    $GLOBALS[ 'WPO365_PLUGIN_DIR' ] = __DIR__;
    
    // Require dependencies
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Logger.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Helpers.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Error_Handler.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Aad/Auth.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/User/User_Manager.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Configs/Required_Plugins_Config.php' );

    // Included for front-end only to be able to test further down the line whether plugins are activated
    include_once( ABSPATH . 'wp-admin/includes/plugin.php' );

    // Track plugin registration
    register_activation_hook( __FILE__, array( '\Wpo\Util\Helpers', 'track' ) );
    add_action( 'plugins_loaded', __NAMESPACE__ . '\Wpo\Util\Helpers::check_version' );
    
    // Ensure session is valid and remains valid
    add_action( 'wp_logout', __NAMESPACE__ . '\Wpo\Aad\Auth::destroy_session' );
    add_action( 'init', __NAMESPACE__ . '\Wpo\Aad\Auth::validate_current_session' );

    // Prevent email address update
    add_action( 'user_profile_update_errors', __NAMESPACE__ . '\Wpo\User\User_Manager::prevent_email_change' );

    // Only allow password changes for non-O365 users and only when already logged on to the system
    add_filter( 'show_password_fields',  __NAMESPACE__ . '\Wpo\User\User_Manager::show_password_change_and_reset' );
    add_filter( 'allow_password_reset', __NAMESPACE__ . '\Wpo\User\User_Manager::show_password_change_and_reset' );
        
    // Enable login message output
    add_filter( 'login_message', __NAMESPACE__ . '\Wpo\Util\Error_Handler::check_for_login_messages' );

    // Configure the options
    add_action( 'plugins_loaded', function ( ) {
        
        if( !is_plugin_active( 'redux-framework/redux-framework.php' ) ) {
            return;
        }
        
        require_once( dirname( __FILE__) . '/Configs/Wpo365_Redux_Config.php' );
    }, 30);

    // Show admin notification when WPO365 not properly configured
    add_action( 'admin_notices', function( ) {

        if( empty( $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ])
            || empty( $GLOBALS[ 'wpo365_options' ][ 'application_id' ])
            || empty( $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ]) ) {

                echo '<div class="notice notice-error"><p>' . __( 'Please visit https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/ for a quick reference on how to properly configure the WPO365-login plugin using the WPO365 menu to your left.' ) . '</p></div>';
                echo '<div class="notice notice-warning is-dismissible"><p>' . __( 'The Wordpress + Office 365 login plugin protects most of Wordpress but in case of a public facing intranet it is strongly advised to block anonymous access to the Wordpress Upload directory' ) . '</p></div>';
                
        }
        
    });
    
?>