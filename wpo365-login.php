<?php
    /**
     *  Plugin Name: WPO365-login
     *  Plugin URI: https://www.wpo365.com/downloads/wordpress-office-365-login/
     *  Github URI: https://github.com/wpo365/wpo365-login
     *  Description: Wordpress + Office 365 login allows Microsoft O365 users to seamlessly and securely log on to your corporate Wordpress intranet. The plugin will create a Wordpress user for each corporate user when logged on to Office 365 and thus avoiding the default Wordpress login screen: No username or password required.
     *  Version: 4.1
     *  Author: info@wpo365.com
     *  Author URI: https://www.wpo365.com
     *  License: GPL2+
     */
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die( );

    $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] = '4.1';
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
    
    // Ensure session is valid and remains valid
    add_action( 'destroy_wpo365_session', __NAMESPACE__ . '\Wpo\Aad\Auth::destroy_session' );

    // Prevent email address update
    add_action( 'personal_options_update', __NAMESPACE__ . '\Wpo\User\User_Manager::prevent_email_change' );

    // Only allow password changes for non-O365 users and only when already logged on to the system
    add_filter( 'show_password_fields',  __NAMESPACE__ . '\Wpo\User\User_Manager::show_password_change_and_reset' );
    add_filter( 'allow_password_reset', __NAMESPACE__ . '\Wpo\User\User_Manager::show_password_change_and_reset' );
        
    // Enable login message output
    add_filter( 'login_message', __NAMESPACE__ . '\Wpo\Util\Error_Handler::check_for_login_messages' );

    // Configure the options
    add_action( 'plugins_loaded', function () {

        require_once( dirname( __FILE__) . '/Configs/Wpo365_Redux_Config.php' );

    });

    // Activate login authentication once the options are loaded
    add_action( 'redux/loaded', function() {

        // In case Redux is used for other plugins
        if( empty( $GLOBALS[ 'wpo365_options' ] ) ) {

            return;
    
        }

        // When multisite then try and obtain settings from the main site in the network
        if( is_multisite() ) {

            // Check for cached options and update when different from main site
            global $current_site;
            $main_site_blog_id = (int)$current_site->blog_id;
            if( get_option( 'wpo365_options' ) != get_blog_option( $main_site_blog_id, 'wpo365_options' ) ) {

                update_option( 'wpo365_options', get_blog_option( 1, 'wpo365_options' ) );

            }

        }

        // Start validating the session as soon as all plugins are loaded
        \Wpo\Aad\Auth::validate_current_session();

        \Wpo\Util\Helpers::check_version();

    } );

    // Add custom wp query vars
    add_filter( 'query_vars', '\Wpo\Util\Helpers::add_query_vars_filter' );

    // Show admin notification when WPO365 not properly configured
    add_action( 'admin_notices', function( ) {

        if( empty( $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ])
            || empty( $GLOBALS[ 'wpo365_options' ][ 'application_id' ])
            || empty( $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ]) ) {

                echo '<div class="notice notice-error"><p>' . __( 'Please visit https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/ for a quick reference on how to properly configure the WPO365-login plugin using the WPO365 menu to your left.' ) . '</p></div>';
                echo '<div class="notice notice-warning is-dismissible"><p>' . __( 'The Wordpress + Office 365 login plugin protects most of Wordpress but in case of a public facing intranet it is strongly advised to block anonymous access to the Wordpress Upload directory' ) . '</p></div>';
                
        }

        if( isset( $_GET[ 'page' ] ) && $_GET[ 'page' ] == 'wpo365-options' ) {

            ?>

            <div class="notice notice-info is-dismissible" style="margin-top: 25px;">
                <article style="display: flex; flex-wrap: wrap; cursor: pointer;" onclick="location.href='https://www.wpo365.com/downloads/wordpress-office-365-login-premium/'">
                    <div style="flex-grow: 0.1; flex-shrink: 0.9;">
                        <img width="256" height="256" src="https://www.wpo365.com/wp-content/uploads/2018/04/premium-icon-256x256.png">
                    </div>
                    <div style="flex-grow: 0.9; flex-shrink: 0.1; padding-left: 10px;">
                        <div>
                            <h2>WordPress + Office 365 login premium</h2>
                        </div>
                        <div >
                            <p>Upgrade today and unlock the following premium features + <strong>support us so we can continue to support you!</strong></p>
                            <ul style="list-style: inherit; margin-left: 20px;">
                                <li>Enriches a user’s WordPress profile with <strong>O365 user profile info</strong> e.g. job title, phone and office location</li>
                                <li>Enhanced <strong>security</strong> e.g. <a href="https://codex.wordpress.org/Brute_Force_Attacks" target="_blank">Brute Force Attacks</a> prevention</li>
                                <li>Replaces a user’s default <strong>WordPress avatar</strong> with the Office 365 (O365) profile picture and caches it</li>
                                <li>Imposes Role Access Control for WordPress based on Office 365 or Azure AD <strong>Security groups</strong></li>
                                <li>Automated WordPress Role Assignment using a <strong>configurable mapping</strong> between Office 365 or Azure AD Security groups and WordPress roles</li>
                                <li>Plain WP_CONFIG configuration (improves the overall <strong>performance</strong> of your website)</li>
                                <li>Integration with <strong>Microsoft Graph</strong></li>
                                <li>One <strong>support</strong> item included</li>
                            </ul>
                        </div>
                    </div>
				</article>
             </div>

            <?php

            echo '<div class="notice notice-warning is-dismissible"><p>' . __( 'The Wordpress + Office 365 login plugin protects most of Wordpress but in case of a public facing intranet it is strongly advised to block anonymous access to the Wordpress Upload directory' ) . '</p></div>';

        }
        
    });

?>