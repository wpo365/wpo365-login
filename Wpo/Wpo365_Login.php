<?php

    namespace Wpo;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Aad\Auth;
    
    if( !class_exists( '\Wpo\Wpo365_Login' ) ) {

        class Wpo365_Login {

            private static $instance;

            private $updateChecker;

            public static function getInstance() {
                
                if( empty( self::$instance ) )
                    self::$instance = new Wpo365_Login();
            }

            private function __construct() {
                $this->on_load();
                $this->add_actions();
                $this->add_filters();
            }

            /**
             * Plugin script is read
             * 
             * @since 4.0
             * 
             * @return void
             */
            private function on_load() {
                require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Configs/Required_Plugins_Config.php' );
            }

            /**
             * When plugins are loaded
             * 
             * @since 4.0
             * 
             * @return void
             */
            public function on_init() {

                // Plugin is using manual configured options in wp-config.php
                if( defined( 'WPO_USE_WP_CONFIG' ) && constant( 'WPO_USE_WP_CONFIG' ) === true ) {
                    $this->init();
                    return;
                }

                // Activate login entication once the options are loaded
                add_action( 'redux/loaded', array( $this, 'redux_loaded' ), 1, 1 );
                
                // else load redux plugin and wpo365 options
                require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Configs/Wpo365_Redux_Config.php' );
            }

            /**
             * When redux is loaded
             * 
             * @since 4.0
             * 
             * @return void
             */
            public function redux_loaded( $reduxFramework ) {

                if( !is_a( $reduxFramework, 'ReduxFramework' ) ) {
                    Logger::write_log( 'DEBUG', 'Redux/Loaded argument exception' );
                    return;
                }

                if( $reduxFramework->args[ 'opt_name' ] != 'wpo365_options' ) {
                    Logger::write_log( 'DEBUG', 'wpo365-login ignoring Redux Framework for ' . $reduxFramework->args[ 'opt_name' ] );
                    return;
                }
                
                $this->init();
            }

            /**
             * Once we are sure our Redux options are loaded
             * 
             * @since 4.0
             * 
             * @return void
             */
            private function init() {
                // Start validating the session as soon as all plugins are loaded
                Auth::validate_current_session();

                // Do super admin stuff
                if( is_admin() && is_super_admin() ) {
                    // Check plugin version
                    Helpers::check_version();
                }
            }

            /**
             * Add all WP actions
             * 
             * @since 4.0
             * 
             * @return void
             */
            private function add_actions() {
                // Configure the options
                add_action( 'plugins_loaded', array( $this, 'on_init' ), 1, 0 );

                // Ensure session is valid and remains valid
                add_action( 'destroy_wpo365_session', '\Wpo\Aad\Auth::destroy_session' );

                // Prevent email address update
                add_action( 'personal_options_update', '\Wpo\User\User_Manager::prevent_email_change', 10, 1 );

                // Show admin notification when WPO365 not properly configured
                add_action( 'admin_notices', '\Wpo\Util\Helpers::show_admin_notices', 10, 0 );

                // Add short code(s)
                add_action( 'init', 'Wpo\Util\Helpers::ensure_short_codes' );

                // Wire up AJAX backend services
                add_action( 'wp_ajax_get_tokencache', '\Wpo\API\Services::get_tokencache' );
            }

            /**
             * Add all WP filters
             * 
             * @since 4.0
             * 
             * @return void
             */
            private function add_filters() {
                // Only allow password changes for non-O365 users and only when already logged on to the system
                add_filter( 'show_password_fields',  '\Wpo\User\User_Manager::show_password_fields', 10, 2 );
                add_filter( 'allow_password_reset', '\Wpo\User\User_Manager::allow_password_reset', 10, 2 );
                    
                // Enable login message output
                add_filter( 'login_message', '\Wpo\Util\Error_Handler::check_for_login_messages' );

                // Add custom wp query vars
                add_filter( 'query_vars', '\Wpo\Util\Helpers::add_query_vars_filter' );
            }
        }
    }