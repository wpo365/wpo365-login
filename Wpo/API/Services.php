<?php

    namespace Wpo\API;

    use \Wpo\Aad\Auth;
    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;

    if( !class_exists( '\Wpo\API\Services' ) ) {
    
        class Services  {

        /**
         * Gets the tokencache with all available bearer tokens
         *
         * @since 4.7
         *
         * @return void
         */
        public static function get_tokencache() {
            if( false === Helpers::get_global_boolean_var( 'WPO_ENABLE_TOKEN_SERVICE' ) )
                wp_die();

            // Verify AJAX request
            $current_user = Services::verify_ajax_request( 'to get the tokencache for a user' );

            // Verify data POSTed
            if( Helpers::get_global_boolean_var( 'WPO_ENABLE_NONCE_CHECK' ) )
                self::verify_POSTed_data( array( 'action', 'nonce', 'resource' ) ); // -> wp_die()
            else
                self::verify_POSTed_data( array( 'action', 'resource' ) ); // -> wp_die()

            if( !empty( $_POST[ 'resource' ] ) ) {
                $resource_info_segments = explode( ',',  $_POST[ 'resource' ] );
                $bearer_token = Auth::get_bearer_token( $resource_info_segments[1] );
                
                if( is_wp_error( $bearer_token ) )
                    self::AJAX_response( 'NOK', $bearer_token->get_error_code(), $bearer_token->get_error_message(), null );
            }

            self::AJAX_response( 'OK', '', '', $bearer_token );
        }

        /**
         * Checks for valid nonce and whether user is logged on and returns WP_User if OK or else
         * writes error response message and return it to requester
         *
         * @since 4.7
         *
         * @param   string      $error_message_fragment used to write a specific error message to the log
         * @return  WP_User if verified or else error response is returned to requester
         */
        protected static function verify_ajax_request( $error_message_fragment )  {
            $error_message = '';

            if ( !is_user_logged_in() )
                $error_message = 'Attempt ' . $error_message_fragment . ' by a user that is not logged on';

            if ( Helpers::get_global_boolean_var( 'WPO_ENABLE_NONCE_CHECK' ) 
                 && ( !isset( $_POST[ 'nonce' ] )
                 || !wp_verify_nonce( $_POST[ 'nonce' ], 'wpo365_fx_nonce' ) ) )
                    $error_message = 'Request ' . $error_message_fragment . ' has been tampered with (invalid nonce)';

            if (strlen($error_message) > 0) {
                Logger::write_log('DEBUG', $error_message);

                $response = array('status' => 'NOK', 'message' => $error_message, 'result' => array());
                wp_send_json($response);
                wp_die();
            }

            return wp_get_current_user();
        }

        /**
         * Stops the execution of the program flow when a key is not found in the the global $_POST
         * variable and returns a given error message
         *
         * @since 4.7
         *
         * @param   array   $keys array of keys to search for
         * @return void
         */
        protected static function verify_POSTed_data( $keys ) {

            foreach ( $keys as $key ) {

                if ( !array_key_exists( $key, $_POST ) ) 
                    self::AJAX_response( 'NOK', '1000', 'Incomplete data posted to complete request: ' . implode( ', ', $keys ), array() );

                $_POST[ $key ] = sanitize_text_field( $_POST[ $key ] );
            }
        }

        /**
         * Helper method to standardize response returned from a Pintra AJAX request
         *
         * @since 4.7
         *
         * @param   string  $status OK or NOK
         * @param   string  $message customer message returned to requester
         * @param   mixed   $result associative array that is parsed as JSON and returned
         * @return void
         */
        protected static function AJAX_response($status, $error_codes, $message, $result) {
            Logger::write_log('DEBUG', "Sending an AJAX response with status $status and message $message");
            wp_send_json(array('status' => $status, 'error_codes' => $error_codes, 'message' => $message, 'result' => $result));
            wp_die();
        }
    }
}
