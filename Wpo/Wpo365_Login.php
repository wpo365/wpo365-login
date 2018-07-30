<?php

    namespace Wpo;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();
    
    use Wpo\Aad\Auth;
    use Wpo\User\User_Manager;
    use Wpo\Util\Error_Handler;
    use Wpo\Util\Helpers;
    use Wpo\Util\Logger;

    if( !class_exists( '\Wpo\Wpo365_Login' ) ) {

        class Wpo365_Login {

            private static $instance;

            public static function getInstance() {

                if( empty( self::$instance ) ) {

                    self::$instance = new Wpo365_Login();
                }
            }

            private function __construct() {

                $this->on_register();
                $this->on_load();
                $this->add_actions();
                $this->add_filters();
            }

            public function on_register() {}

            private function on_load() {

                Helpers::disable_spo_plugin();

                include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
                require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Required_Plugins.php' );
                require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Configs/Required_Plugins_Config.php' );
            }

            private function add_actions() {

                // Ensure session is valid and remains valid
                add_action( 'destroy_wpo365_session', '\Wpo\Aad\Auth::destroy_session' );

                // Prevent email address update
                add_action( 'personal_options_update', '\Wpo\User\User_Manager::prevent_email_change' );

                // Configure the options
                add_action( 'plugins_loaded', function () {

                    require_once( dirname( dirname( __FILE__) ) . '/Configs/Wpo365_Redux_Config.php' );
                });

                // Activate login authentication once the options are loaded
                add_action( 'redux/loaded', function( $reduxFramework ) {

                    if( !is_a( $reduxFramework, 'ReduxFramework' ) ) {

                        Logger::write_log( 'DEBUG', 'Redux/Loaded argument exception' );
                        return;
                    }

                    if( $reduxFramework->args[ 'opt_name' ] != 'wpo365_options' ) {

                        Logger::write_log( 'DEBUG', 'wpo365-login ignoring Redux Framework for ' . $reduxFramework->args[ 'opt_name' ] );
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
                    Auth::validate_current_session();

                    Helpers::check_version();

                }, 1, 1 );

                // Show admin notification when WPO365 not properly configured
                add_action( 'admin_notices', '\Wpo\Util\Helpers::show_admin_notices', 10, 0 );
            }

            private function add_filters() {

                // Only allow password changes for non-O365 users and only when already logged on to the system
                add_filter( 'show_password_fields',  '\Wpo\User\User_Manager::show_password_change_and_reset' );
                add_filter( 'allow_password_reset', '\Wpo\User\User_Manager::show_password_change_and_reset' );

                // Enable login message output
                add_filter( 'login_message', '\Wpo\Util\Error_Handler::check_for_login_messages' );

                // Add custom wp query vars
                add_filter( 'query_vars', '\Wpo\Util\Helpers::add_query_vars_filter' );   
            }
        }
    }