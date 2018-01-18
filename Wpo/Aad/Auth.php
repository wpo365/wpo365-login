<?php
    namespace Wpo\Aad;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();

    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Logger.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Helpers.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Error_Handler.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/User/User_Manager.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Firebase/JWT/JWT.php' );

    
    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Util\Error_Handler;
    use \Wpo\User\User_Manager;
    use \Firebase\JWT\JWT;
    
    class Auth {

        const USR_META_WPO365_AUTH = 'WPO365_AUTH';
        const USR_META_WPO365_AUTH_CODE = 'WPO365_AUTH_CODE';

        /**
         * Destroys any session and authenication artefacts and hooked up with wp_logout and should
         * therefore never be called directly to avoid endless loops etc.
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function destroy_session() {
            
            Logger::write_log( 'DEBUG', 'Destroying session ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) );
            
            Auth::delete_user_meta( Auth::USR_META_WPO365_AUTH );

        }

        /**
         * Same as destroy_session but with redirect to login page
         *
         * @since   1.0
         * @return  void
         */
        public static function goodbye() {

            // Only redirect to login page when user is not already there 
            if( strpos( strtolower( wp_login_url() ), 
                strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) ) === false ) {

                    wp_logout(); // This will also call destroy_session because of wp_logout hook
                    auth_redirect();

            }
            
        }

        /**
         * Validates each incoming request to see whether user prior to request
         * was authenicated by Microsoft Office 365 / Azure AD.
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function validate_current_session() {
            
            // Check if WPO365 is unconfigured and if so redirect to login page
            if( ( !isset( $GLOBALS[ 'wpo365_options' ] )
                || empty( $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ] )
                || empty( $GLOBALS[ 'wpo365_options' ][ 'application_id' ] )
                || empty( $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ] ) ) 
                && !is_user_logged_in() ) {
                
                Logger::write_log( 'ERROR', 'WPO365 not configured' );
                Error_Handler::add_login_message( __( 'Wordpress + Office 365 login not configured yet. Please contact your System Administrator.' ) );
                Auth::goodbye();
                return;

            }

            // Check for error in data posted
            if( isset( $_POST[ 'error' ] ) ) {
            
                $error_string = $_POST[ 'error' ] . isset( $_POST[ 'error_description' ] ) ? $_POST[ 'error_description' ] : '';
                Logger::write_log( 'ERROR', $error_string );
                Error_Handler::add_login_message( $_POST[ 'error' ] . __( '. Please contact your System Administrator.' ) );
                Auth::goodbye();
            
            }

            // Check for new ( id_tokens ) tokens in data posted
            if( isset( $_POST[ 'state' ] ) && isset( $_POST[ 'id_token' ] ) ) {

                \Wpo\Aad\Auth::process_openidconnect_token();

            }

            // Check is scenario is 'internet' and validation of current page can be skipped
            if( isset( $GLOBALS[ 'wpo365_options' ] )
                && isset( $GLOBALS[ 'wpo365_options' ][ 'auth_scenario' ] )
                && $GLOBALS[ 'wpo365_options' ][ 'auth_scenario' ] == '2'
                && !is_admin() ) {

                    Logger::write_log( 'DEBUG', 'Cancelling session validation for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) . ' because selected scenario is \'Internet\'' );
                    return;

            }
            
            Logger::write_log( 'DEBUG', 'Validating session for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) );
            
            // Check if current page is blacklisted and can be skipped
            if( isset( $GLOBALS[ 'wpo365_options' ] )
                && !empty( $GLOBALS[ 'wpo365_options' ][ 'pages_blacklist' ] ) 
                && strpos( strtolower( $GLOBALS[ 'wpo365_options' ][ 'pages_blacklist' ] ), 
                   strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) ) !== false ) {

                Logger::write_log( 'DEBUG', 'Cancelling session validation for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) );

                return;

            }

            $wpo_auth = Auth::get_unique_user_meta( Auth::USR_META_WPO365_AUTH );

            // Check if Wordpress-only user that is already logged on
            if( $wpo_auth === NULL ) {

                Logger::write_log( 'DEBUG', 'User is a Wordpress-only user so no authentication is required' );
                return;

            }
            
            // Check if user either not logged or has login that is no longer valid
            if( $wpo_auth === false
                || Auth::check_user_meta_is_expired( Auth::USR_META_WPO365_AUTH, $wpo_auth ) ) { 

                wp_logout(); // logout but don't redirect to the login page
                Logger::write_log( 'DEBUG', 'User either not logged on or has login is not longer valid' );
                Auth::get_openidconnect_and_oauth_token();
            }

            // Everything OK

        }

        /**
         * Sets a user meta field in a safe way so that user is logged in and value
         * is updated instead of added if already exist
         *
         * @since   2.0
         *
         * @param   string  $key as user meta key
         * @param   string  $value as user meta value
         * @return  bool    true if user meta was added or updated or else false
         */
        public static function set_unique_user_meta( $key, $value ) {

            if( !is_user_logged_in() ) {
                
                Logger::write_log( 'DEBUG', 'Cannot look up user meta ' . $key . ' for user that is not logged' );
                return false;
            
            }

            $wp_usr = wp_get_current_user();
            $usr_meta = get_user_meta( $wp_usr->ID );

            if( !isset( $usr_meta[ $key ] ) ) {
                
                add_user_meta( $wp_usr->ID, $key, $value, true );
                
                Logger::write_log( 'DEBUG', 'Set user meta for ' . $key );
                return true;
            
            }
            else {
            
                update_user_meta( $wp_usr->ID, $key, $value );
                
                Logger::write_log( 'DEBUG', 'Updated user meta for ' . $key );
                return true;
            
            }

        }

        /**
         * Deletes a user meta field in a safe way so that user is logged in
         *
         * @since   2.0
         *
         * @param   string  $key as user meta key
         * @return  void if user meta was deleted successfully or false if something went wrong
         */
        public static function delete_user_meta( $key ) {

            if( !is_user_logged_in() ) {
                
                Logger::write_log( 'DEBUG', 'Cannot look up user meta ' . $key . ' for user that is not logged' );
                return false;
            
            }

            $wp_usr = wp_get_current_user();

            delete_user_meta( $wp_usr->ID, $key ); // Potentially the user is logged on as a Worp<
            
            Logger::write_log( 'DEBUG', 'Tried deleting user meta for ' . $key );
        }

        /**
         * Returns user meta if found or else false
         *
         * @since   2.0
         *
         * @param   string  $key as user meta key
         * @return  user meta as string if found or else NULL for a logged in user or false if user is not logged in
         */
        public static function get_unique_user_meta( $key ) {

            if( !is_user_logged_in() ) {
                
                Logger::write_log( 'DEBUG', 'Cannot look up user meta ' . $key . ' for user that is not logged' );
                return false;
            
            }
                
            $wp_usr = wp_get_current_user();
            $usr_meta = get_user_meta( $wp_usr->ID );

            if( !isset( $usr_meta[ $key ] )
                || sizeof( $usr_meta[ $key ] ) != 1 ) {

                    Logger::write_log( 'DEBUG', 'No user meta found for ' . $key );
                    return NULL;
                        
            }

            return $usr_meta[ $key ][0];

        }

        /**
         * Verifies whether a user meta field that is formatted as 'expiration,value'  
         * is expired according to its expiration fragment and if expired will delete
         * the user meta field
         *
         * @since   2.0
         *
         * @param   string  $key as user meta key
         * @param   string  $value as user meta vaue formatted as 'expiration,value'
         * @return  true when expired or else false
         */
        public static function check_user_meta_is_expired( $key, $value ) {

            $value_with_expiry  = explode( ',', $value );

            if( sizeof( $value_with_expiry ) != 2
                || intval( $value_with_expiry[0] ) < time() ) { 

                Auth::delete_user_meta( $key );
                Logger::write_log( 'DEBUG', 'Expired user meta deleted for ' . $key );

                return true;

            }

            return false;

        }

        /**
         * Gets authorization and id_tokens from Microsoft authorization endpoint by redirecting the user. The
         * state parameter is used to restore the user's state ( = requested page ) when redirected back to Wordpress
         * 
         * NOTE The refresh token is not used because it cannot be used to authenticate a user ( no id_token )
         * See https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code 
         *
         * @since   1.0
         *
         * @return  void 
         */
        public static function get_openidconnect_and_oauth_token() {

            $params = array( 
                'client_id'     => $GLOBALS[ 'wpo365_options' ][ 'application_id' ],
                'response_type' => 'id_token code',
                'redirect_uri'  => $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ],
                'response_mode' => 'form_post',
                'scope'         => $GLOBALS[ 'wpo365_options' ][ 'scope' ],
                'resource'      => $GLOBALS[ 'wpo365_options' ][ 'aad_resource_uri' ],
                'state'         => ( isset( $_SERVER[ 'HTTPS' ] ) ? 'https' : 'http' ) . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                'nonce'         => wp_create_nonce( 'aad_auth' ),
            );

            $authorizeUrl = 'https://login.microsoftonline.com/' . $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ] . '/oauth2/authorize?' . http_build_query( $params, '', '&' );
            Logger::write_log( 'DEBUG', 'Getting fresh id and authorization tokens: ' . $authorizeUrl );

            // Redirect to Microsoft Authorization Endpoint
            wp_redirect( $authorizeUrl );
            exit(); // exit after redirect
        }

        /**
         * Handles redirect from Microsofts authorization service and tries to detect
         * any wrong doing and if detected redirects wrong-doer to Wordpress login instead
         *
         * @since   1.0
         * @return  void
         */
         public static function process_openidconnect_token() {
            
            Logger::write_log( 'DEBUG', 'Processing incoming OpenID Connect id_token' );

            // Decode the id_token
            $id_token = Auth::decode_id_token();

            // Handle if token could not be processed or nonce is invalid
            if( $id_token === false || $id_token->nonce != wp_create_nonce( 'aad_auth' ) ) {

                Error_Handler::add_login_message( __( 'Your login might be tampered with. Please contact your System Administrator.' ) );
                Logger::write_log( 'ERROR', 'id token could not be processed and user will be redirected to default Wordpress login' );

                Auth::goodbye();

            }
        
            // Ensure user with the information found in the id_token
            $usr = User_Manager::ensure_user( $id_token );
            
            // Handle if user could not be processed
            if( $usr === false ) {

                Error_Handler::add_login_message( __( 'Could not create or retrieve your login. Please contact your System Administrator.' ) );
                Logger::write_log( 'ERROR', 'Could not get or create Wordpress user' );

                Auth::goodbye();
            }

            // Store the Authorization Code for extensions that may need it to obtain access codes for AAD secured resources
            if( isset( $_POST[ 'code' ] ) ) {

                Auth::set_unique_user_meta( Auth::USR_META_WPO365_AUTH_CODE, ''. ( time() + 120 ) . ',' . $_POST[ 'code' ] );

            }

            // Allow other Wordpress extensions to get additional tokens e.g. for SharePoint Online or Microsoft Graph
            do_action( 'wpo365_openid_token_processed' );

            // User could log on and everything seems OK so let's restore his state
            Logger::write_log( 'DEBUG', 'Redirecting to ' . $_POST[ 'state' ] );
            wp_redirect( $_POST[ 'state' ] );
            exit(); // Always exit after a redirect

        }

        /**
         * Unraffles the incoming JWT id_token with the help of Firebase\JWT and the tenant specific public keys available from Microsoft.
         * 
         * NOTE The refresh token is not used because it cannot be used to authenticate a user ( no id_token )
         * See https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-openid-connect-code 
         *
         * @since   1.0
         *
         * @return  void 
         */
        private static function decode_id_token() {

            Logger::write_log( 'DEBUG', 'Processing an new id token' );

            // Check whether an id_token is found in the posted payload
            if( !isset( $_POST[ 'id_token' ] ) ) {
                Logger::write_log( 'ERROR', 'id token not found' );
                return false;
            }

            // Get the token and get it's header for a first analysis
            $id_token = $_POST[ 'id_token' ];
            $jwt_decoder = new JWT();
            $header = $jwt_decoder::header( $id_token );
            
            // Simple validation of the token's header
            if( !isset( $header->kid ) || !isset( $header->alg ) ) {

                Logger::write_log( 'ERROR', 'JWT header is missing so stop here' );
                return false;

            }

            Logger::write_log( 'DEBUG', 'Algorithm found ' . $header->alg );

            // Discover tenant specific public keys
            $keys = Auth::discover_ms_public_keys();
            if( $keys == NULL ) {

                Logger::write_log( 'ERROR', 'Could not retrieve public keys from Microsoft' );
                return false;

            }

            // Find the tenant specific public key used to encode JWT token
            $key = Auth::retrieve_ms_public_key( $header->kid, $keys );
            if( $key == false ) {

                Logger::write_log( 'ERROR', 'Could not find expected key in keys retrieved from Microsoft' );
                return false;

            }

            $pem_string = "-----BEGIN CERTIFICATE-----\n" . chunk_split( $key, 64, "\n" ) . "-----END CERTIFICATE-----\n";

            // Decode athe id_token
            $decoded_token = $jwt_decoder::decode( 
                $id_token, 
                $pem_string,
                array( strtoupper( $header->alg ) )
            );

            if( !$decoded_token ) {

                Logger::write_log( 'ERROR', 'Failed to decode token ' . substr( $pem_string, 0, 35 ) . '...' . substr( $pem_string, -35 ) . ' using algorithm ' . $header->alg );
                return false;

            }

            return $decoded_token;

        }

        /**
         * Discovers the public keys Microsoft used to encode the id_token
         *
         * @since   1.0
         *
         * @return  void 
         */
        private static function discover_ms_public_keys() {

            $ms_keys_url = 'https://login.microsoftonline.com/common/discovery/keys';
            $curl = curl_init();

            curl_setopt( $curl, CURLOPT_URL, $ms_keys_url );
            curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );

            if( isset( $GLOBALS[ 'wpo365_options' ] )
                && isset( $GLOBALS[ 'wpo365_options' ][ 'skip_host_verification' ] )
                && $GLOBALS[ 'wpo365_options' ][ 'skip_host_verification' ] == 1 ) {

                    Logger::write_log( 'DEBUG', 'Skipping SSL peer and host verification' );

                    curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                    curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 

            }

            Logger::write_log( 'DEBUG', 'Getting current public keys from MSFT' );
            $result = curl_exec( $curl ); // result holds the keys
            if( curl_error( $curl ) ) {
                
                // TODO handle error
                Logger::write_log( 'ERROR', 'error occured whilst getting a token: ' . curl_error( $curl ) );
                return NULL;

            }
            
            curl_close( $curl );

            $keys = json_decode( $result );

            if( isset( $keys->keys ) ) {

                return $keys->keys;

            } 
            else {

                return $keys;                

            }

        }
    
        /**
         * Retrieves the ( previously discovered ) public keys Microsoft used to encode the id_token
         *
         * @since   1.0
         *
         * @param   string  key-id to retrieve the matching keys
         * @param   array   keys previously discovered
         * @return  void 
         */
        private static function retrieve_ms_public_key( $kid, $keys ) {

            foreach( $keys as $key ) {

                if( $key->kid == $kid ) {

                    if( is_array( $key->x5c ) ) {
                        return $key->x5c[0];
                    }
                    else {
                        return $key->x5c;
                    }
                }
            }
            return false;
        }

        /**
         * Parses url the user should be redirected to upon successful logon
         *
         * @since   1.0
         *
         * @param   string  url => redirect_to parameter set by Wordpress
         * @return  string  redirect_to or site url 
         */
        private static function get_redirect_to( $url ) {

            // Return base url if argument is missing
            if( empty( $url ) ) {
                return get_site_url();
            }

            $query_string = explode( '?', $url );
            parse_str( $query_string, $out );
            
            if( isset( $out[ 'redirect_to' ] ) ) {
                Logger::write_log( 'DEBUG', 'Redirect URL found and parsed: ' . $out[ 'redirect_to' ] );
                return $out[ 'redirect_to' ];
            }

            return get_site_url();
        }
                
    }
?>