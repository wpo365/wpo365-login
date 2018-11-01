<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Util\Helpers;

    if( !class_exists( '\Wpo\Util\Error_Handler' ) ) {

        class Error_Handler {

            const NOT_CONFIGURED        = 'NOT_CONFIGURED';
            const CHECK_LOG             = 'CHECK_LOG';
            const TAMPERED_WITH         = 'TAMPERED_WITH';
            const USER_NOT_FOUND        = 'USER_NOT_FOUND';
            const NOT_IN_GROUP          = 'NOT_IN_GROUP';
            const PERSONAL_BLOG_LIMIT   = 'PERSONAL_BLOG_LIMIT';
            
            /**
             * Checks for errors in the login messages container and display and unset immediatly after if any
             *
             * @since   1.0
             * @return  void
             */
            public static function check_for_login_messages() {

                if( !isset( $_GET[ 'login_errors' ] ) ) {

                    return;
                }

                // Using $_GET here since wp_query is not loaded on login page
                $login_error_codes = $_GET[ 'login_errors' ];

                $result = '';

                foreach( explode( ',', $login_error_codes ) as $login_error_code ) {

                    $result .= '<p class="message">' . self::get_error_message( $login_error_code ) . '</p><br />';
                }
                
                // Return messages to display to hook
                return $result;
            }

            /**
             * Tries to get an error message for the error code provided either from
             * the options or else from the hard coded backup dictionary provided.
             * 
             * @since 0.1
             * 
             * @param string $error_code Error code
             * @return string Error message
             */
            public static function get_error_message( $error_code ) {

                $error_messages = Array(
                    self::NOT_CONFIGURED        => __( 'Wordpress + Office 365 login not configured yet. Please contact your System Administrator.' ),
                    self::CHECK_LOG             => __( 'Please contact your System Administrator and check log file.' ),
                    self::TAMPERED_WITH         => __( 'Your login might be tampered with. Please contact your System Administrator.' ),
                    self::USER_NOT_FOUND        => __( 'Could not create or retrieve your login. Please contact your System Administrator.' ),
                    self::NOT_IN_GROUP          => __( 'Access Denied. Please contact your System Administrator.' ),
                    self::PERSONAL_BLOG_LIMIT   => __( 'Cannot create more than three users with the Personal Blog (free) version of the plugin. Please <a href="https://www.wpo365.com/downloads/wordpress-office-365-login-premium/">upgrade</a> or create additional users manually.' ),
                );

                $error_message = Helpers::get_global_var( 'WPO_ERROR_' . $error_code );

                if( is_wp_error( $error_message ) )
                    return array_key_exists( $error_code, $error_messages )
                        ? $error_messages[ $error_code ]
                        : '';

                return $error_message;
            }
        }
    }

?>