<?php
    namespace Wpo\Aad;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Util\Error_Handler;
    use \Wpo\User\User_Manager;
    use \Wpo\Firebase\JWT\JWT;

    if( !class_exists( '\Wpo\Aad\Auth' ) ) {
    
        class Auth {

            const USR_META_WPO365_AUTH      = 'WPO365_AUTH';
            const USR_META_WPO365_AUTH_CODE = 'WPO365_AUTH_CODE';
       
            const USR_META_REFRESH_TOKEN_PREFIX = 'wpo_refresh_token_for_';
            const USR_META_ACCESS_TOKEN_PREFIX  = 'wpo_access_token_for_';
            
            /**
             * Destroys any session and authenication artefacts and hooked up with wpo365_logout and should
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
            public static function goodbye( $login_error_code ) {

                // Only redirect to login page when user is not already there 
                if( strpos( strtolower( wp_login_url() ), 
                    strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) ) === false ) {

                        do_action( 'destroy_wpo365_session' );

                        wp_logout();

                        $login_url = wp_login_url( '', true );
                        
                        $login_url = add_query_arg( 'login_errors', $login_error_code, $login_url );
                        
                        Helpers::force_redirect( $login_url );
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

                    Auth::goodbye( Error_Handler::NOT_CONFIGURED );

                    return;

                }

                // Check for error in data posted
                if( isset( $_POST[ 'error' ] ) ) {
                
                    $error_string = $_POST[ 'error' ] . isset( $_POST[ 'error_description' ] ) ? $_POST[ 'error_description' ] : '';

                    Logger::write_log( 'ERROR', $error_string );

                    Auth::goodbye( Error_Handler::CHECK_LOG );
                    
                    return;
                
                }

                // Check for new ( id_tokens ) tokens in data posted
                if( isset( $_POST[ 'state' ] ) && isset( $_POST[ 'id_token' ] ) ) {

                    \Wpo\Aad\Auth::process_openidconnect_token();
                    return;

                }

                // Check is scenario is 'internet' and validation of current page can be skipped
                if( isset( $GLOBALS[ 'wpo365_options' ] )
                    && isset( $GLOBALS[ 'wpo365_options' ][ 'auth_scenario' ] )
                    && $GLOBALS[ 'wpo365_options' ][ 'auth_scenario' ] == '2'
                    && !is_admin() ) {

                        Logger::write_log( 'DEBUG', 'Cancelling session validation for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) . ' because selected scenario is \'Internet\'' );
                        return;

                }
                
                Logger::write_log( 'DEBUG', 'Validating session for path ' . strtolower( $_SERVER[ 'REQUEST_URI' ] ) );
                
                // Check if current page is blacklisted and can be skipped
                if( isset( $GLOBALS[ 'wpo365_options' ] )
                    && !empty( $GLOBALS[ 'wpo365_options' ][ 'pages_blacklist' ] ) ) {

                        $black_listed_pages = explode( ';', strtolower( trim( $GLOBALS[ 'wpo365_options' ][ 'pages_blacklist' ] ) ) );
                        $request_uri = strtolower( $_SERVER[ 'REQUEST_URI' ] );

                        foreach( $black_listed_pages as $black_listed_page ) {

                            if( empty( $black_listed_page ) ) {

                                continue;
                            }
                            
                            // Correction after the plugin switched from basename to path based comparison
                            $starts_with = substr( $black_listed_page, 0, 1);
                            $black_listed_page = $starts_with == '/' || $starts_with == '?' ? $black_listed_page : '/' . $black_listed_page;
                            
                            // Filter out any attempt to illegally bypass authentication
                            if( strpos( $request_uri, '?/' ) !== false ) {

                                Logger::write_log( 'ERROR', 'Serious attempt to try to bypass authentication using an illegal query string combination "?/" (path used: ' . $request_uri . ')');
                                break;
                            }
                            elseif( strpos( $request_uri, $black_listed_page ) !== false ) {

                                Logger::write_log( 'DEBUG', 'Found [' . $black_listed_page . '] thus cancelling session validation for path ' . $request_uri );
                                return;
                            }
                        }
                }

                $wpo_auth = Auth::get_unique_user_meta( Auth::USR_META_WPO365_AUTH );

                // Logged-on WP-only user
                if( $wpo_auth === NULL ) {

                    Logger::write_log( 'DEBUG', 'User is a Wordpress-only user so no authentication is required' );
                    return;

                }
                
                // User not logged on
                if( $wpo_auth === false ) {
                    
                    Auth::get_openidconnect_and_oauth_token();
                    
                    return;
                }

                // Check if user has expired 
                if( Auth::check_user_meta_is_expired( Auth::USR_META_WPO365_AUTH, $wpo_auth ) ) {

                    do_action( 'destroy_wpo365_session' );
                
                    wp_logout();

                    wp_set_current_user( 0 );

                    unset($_COOKIE[AUTH_COOKIE]);
                    unset($_COOKIE[SECURE_AUTH_COOKIE]);
                    unset($_COOKIE[LOGGED_IN_COOKIE]);

                    Logger::write_log( 'DEBUG', 'User logged out because current login not valid anymore' );

                    Auth::get_openidconnect_and_oauth_token();

                    return;
                
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

                update_user_meta( get_current_user_id(), $key, $value );
                    
                Logger::write_log( 'DEBUG', 'Updated user meta for ' . $key );
                
                return true;

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
                    
                    Logger::write_log( 'DEBUG', 'Cannot delete user meta ' . $key . ' for user that is not logged' );
                    return false;
                
                }

                delete_user_meta( get_current_user_id(), $key ); // Potentially the user is logged on as a Worp<
                
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
                    
                $usr_meta = get_user_meta( get_current_user_id(), $key, true );

                return empty($usr_meta) ? NULL : $usr_meta;
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
                    'state'         => ( strpos( $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ], 'https' ) !== false ? 'https' : 'http' ) . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                    'nonce'         => Helpers::get_nonce(),
                );

                $authorizeUrl = 'https://login.microsoftonline.com/' . $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ] . '/oauth2/authorize?' . http_build_query( $params, '', '&' );
                Logger::write_log( 'DEBUG', 'Getting fresh id and authorization tokens: ' . $authorizeUrl );

                // Redirect to Microsoft Authorization Endpoint
                Helpers::force_redirect( $authorizeUrl );
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
                if( $id_token === false || Helpers::validate_nonce( $id_token->nonce ) !== true ) {

                    Logger::write_log( 'ERROR', 'id token could not be processed and user will be redirected to default Wordpress login' );

                    Auth::goodbye( Error_Handler::TAMPERED_WITH );

                }
            
                // Ensure user with the information found in the id_token
                $usr = User_Manager::ensure_user( $id_token );
                
                // Handle if user could not be processed
                if( $usr === false ) {

                    Logger::write_log( 'ERROR', 'Could not get or create Wordpress user' );

                    Auth::goodbye( Error_Handler::USER_NOT_FOUND );
                }

                // Store the Authorization Code for extensions that may need it to obtain access codes for AAD secured resources
                if( isset( $_POST[ 'code' ] ) ) {

                    Auth::set_unique_user_meta( Auth::USR_META_WPO365_AUTH_CODE, ''. ( time() + 120 ) . ',' . $_POST[ 'code' ] );

                }

                // Allow other Wordpress extensions to get additional tokens e.g. for SharePoint Online or Microsoft Graph
                do_action( 'wpo365_openid_token_processed' );

                // User could log on and everything seems OK so let's restore his state
                Logger::write_log( 'DEBUG', 'Redirecting to ' . $_POST[ 'state' ] );
                Helpers::force_redirect( $_POST[ 'state' ] );
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
             * Gets an access token in exchange for an authorization token that was received prior when getting
             * an OpenId Connect token or for a fresh code in case available
             *
             * @since   5.0
             *
             * @param   string  AAD secured resource for which the access token should give access
             * @return  object  access token as PHP std object
             */
            public static function get_access_token( $resource, $resource_uri ) {

                Logger::write_log( 'DEBUG', 'Requesting access token for ' . $resource . ' using ' . $resource_uri );
                
                // Check to see if a refresh code is available
                $refresh_token = self::get_refresh_token_for_resource( $resource );

                // Check to see if an authorization code from logging on is available
                $auth_code = self::get_unique_user_meta( Auth::USR_META_WPO365_AUTH_CODE );

                // If not check to see if an authorization code is available
                if( $refresh_token === false 
                    && ( $auth_code === false                                                                   // user not logged in
                    || $auth_code === NULL                                                                      // no code found
                    || Auth::check_user_meta_is_expired( Auth::USR_META_WPO365_AUTH_CODE, $auth_code ) ) ) {    // code expired

                            Logger::write_log( 'ERROR', 'Could not get access code because of missing authorization or refresh code' );
                            return false;
                }

                $params = NULL;
                if( $refresh_token !== false ) {

                    $params = array( 
                        'grant_type' => 'refresh_token',
                        'client_id' => $GLOBALS[ 'wpo365_options' ][ 'application_id' ],
                        'refresh_token' => $refresh_token,
                        'resource' => $resource_uri,
                        'client_secret' => $GLOBALS[ 'wpo365_options' ][ 'application_secret' ]
                    );
                }
                else {

                    $auth_code_segments = explode( ',', $auth_code );

                    $params = array( 
                        'grant_type' => 'authorization_code',
                        'client_id' => $GLOBALS[ 'wpo365_options' ][ 'application_id' ],
                        'code' => $auth_code_segments[1],
                        'resource' => $resource_uri,
                        'redirect_uri' => $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ],
                        'client_secret' => $GLOBALS[ 'wpo365_options' ][ 'application_secret' ]
                    );
                }

                $params_as_str = http_build_query( $params, '', '&' ); // Fix encoding of ampersand
                $authorizeUrl = 'https://login.microsoftonline.com/common/oauth2/token';
                
                $curl = curl_init();
                curl_setopt( $curl, CURLOPT_POST, 1 );
                curl_setopt( $curl, CURLOPT_URL, $authorizeUrl );
                curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );
                curl_setopt( $curl, CURLOPT_POSTFIELDS, $params_as_str );
                curl_setopt( $curl, CURLOPT_HTTPHEADER, array( 
                    'Content-Type: application/x-www-form-urlencoded'
                ) );

                if( isset( $GLOBALS[ 'wpo365_options' ] )
                    && isset( $GLOBALS[ 'wpo365_options' ][ 'skip_host_verification' ] )
                    && $GLOBALS[ 'wpo365_options' ][ 'skip_host_verification' ] == 1 ) {

                        Logger::write_log( 'DEBUG', 'Skipping SSL peer and host verification' );

                        curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                        curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 

                }
            
                $result = curl_exec( $curl ); // result holds the tokens
            
                if( curl_error( $curl ) ) {

                    Logger::write_log( 'ERROR', 'Error occured whilst getting an access token (' . curl_error( $curl ) . ')' );
                    curl_close( $curl );

                    return false;
                }
            
                curl_close( $curl );

                // Validate the access token and return it
                $access_token_obj = json_decode( $result );
                $access_token_is_valid = Auth::validate_access_token( $access_token_obj );

                if( $access_token_is_valid === false ) {

                    Logger::write_log( 'ERROR', 'Could not get a valid access token for ' . $resource );
                    return false;
                }

                // Save refresh token
                Auth::set_refresh_token_for_resource( $resource, $access_token_obj->refresh_token );

                Logger::write_log( 'DEBUG', 'Successfully obtained a valid access token for ' . $resource );
                // Logger::write_log( 'DEBUG', $access_token_obj );

                return $access_token_obj;
            }

            /**
             * Helper to validate an oauth access token
             *
             * @since   4.0
             *
             * @param   object  access token as PHP std object
             * @return  object  access token as PHP std object or false if not valid
             * @todo    make by reference instead by value
             */
            private static function validate_access_token( $access_token_obj ) {
                
                if( isset( $access_token_obj->error ) ) {

                    Logger::write_log( 'ERROR', 'Error found whilst validating access token: ' . $access_token_obj->error_description );
                    return false;
                }
            
                if( empty( $access_token_obj ) 
                    || $access_token_obj === false
                    || !isset( $access_token_obj->access_token ) 
                    || !isset( $access_token_obj->expires_in ) 
                    || !isset( $access_token_obj->refresh_token )
                    || !isset( $access_token_obj->token_type )
                    || !isset( $access_token_obj->resource )
                    || strtolower( $access_token_obj->token_type ) != 'bearer' ) {
            
                    Logger::write_log( 'ERROR', 'Incomplete access code detected' );
                    return false;
                }
            
                return $access_token_obj;
            }

            /**
             * Searches for an existing access token given the user meta data key
             * And if found checks if expired.
             * 
             * @since 4.0
             * 
             * @param string $user_meta_key User meta key as string
             * 
             * @return boolean true if exists otherwise false
             */
            public static function access_token_for_resource_exists( $usr_meta_key ) {

                $usr_meta_value = Auth::get_unique_user_meta( $usr_meta_key );

                if( empty( $usr_meta_value ) ) {

                    Logger::write_log( 'DEBUG', 'No access token found for ' . $usr_meta_key );
                    return false;
                }

                if( Auth::check_user_meta_is_expired( $usr_meta_key, $usr_meta_value ) ) {

                    return false;
                }

                Logger::write_log( 'DEBUG', 'Found a valid access token for ' . $usr_meta_key );
                return true;
            }

            /**
             * Tries and find a refresh token for an AAD resource stored as user meta in the form "expiration,token"
             * In case an expired token is found it will be deleted
             *
             * @since   4.0
             * 
             * @param   string  $resource   Name for the resource key used to store that resource in the site options
             * @return  refresh token as string or false if not found or expired
             */
            private static function get_refresh_token_for_resource( $resource ) {
                
                $usr_meta_key = Auth::USR_META_REFRESH_TOKEN_PREFIX . $resource;
                $usr_meta_value = Auth::get_unique_user_meta( $usr_meta_key );

                if( $usr_meta_value === false
                    || $usr_meta_value === NULL
                    || Auth::check_user_meta_is_expired( $usr_meta_key, $usr_meta_value ) ) {

                        Logger::write_log( 'DEBUG', 'Could not find a valid refresh token for ' . $resource );
                        return false;

                }

                Logger::write_log( 'DEBUG', 'Found refresh token in user meta for ' . $resource );
                $usr_meta_value_segments = explode( ',', $usr_meta_value);

                return $usr_meta_value_segments[1];
            }

            /**
             * Sets a refresh token as user meta in the form "expiration,token"
             *
             * @since   4.0
             * 
             * @param   string  $resource name   Name for the resource key as used to store that resource in the site options
             * @return  void or false if not able to store the token
             */
            private static function set_refresh_token_for_resource( $resource, $refresh_token ) {

                $usr_meta_key = Auth::USR_META_REFRESH_TOKEN_PREFIX . $resource;
                $session_duration = $GLOBALS[ 'wpo365_options' ][ 'session_duration' ];
                $session_duration = is_wp_error( $session_duration ) ? 3480 : $session_duration;
                $refresh_token_with_expiry = strval( time( ) + intval( $session_duration ) ) . ',' . $refresh_token;
                Auth::set_unique_user_meta( $usr_meta_key, $refresh_token_with_expiry );

                Logger::write_log( 'DEBUG', 'Successfully stored refresh token as user meta for ' . $resource );
            }

            /**
             * Compares ttl of token passed as an argument with the auth cookie ttl and returns the shortest ttl
             *
             * @since 0.1
             *
             * @param   int     $expires_in is the ttl in seconds of an oauth access token
             * @return  int     ttl in seconds possibly corrected for ttl of auth cookie
             */
            public static function calculate_shortest_ttl( $token_expires_in ) {

                $token_expiry = time() + intval( $token_expires_in );
                $wpo_auth = Auth::get_unique_user_meta( Auth::USR_META_WPO365_AUTH );
                
                // Check if Wordpress-only user that is already logged on
                if( $wpo_auth === NULL ) {
                
                    Logger::write_log( 'DEBUG', 'User is a logged on with a Wordpress-only login so cannot calculate shortest ttl' );
                    return $token_expiry;
                }
                
                // Check if user either not logged or has login that is no longer valid
                if( $wpo_auth === false
                    || Auth::check_user_meta_is_expired( Auth::USR_META_WPO365_AUTH, $wpo_auth ) ) { 
                                
                        do_action( 'destroy_wpo365_session' );
                        Logger::write_log( 'DEBUG', 'User either not logged on or has login is not longer valid so instead of caluclating shortest ttl login is refreshed' );
                        Auth::get_openidconnect_and_oauth_token();
                }

                $wpo_auth_segments = explode( ',', $wpo_auth );
                $wpo_auth_expiry  = intval( $wpo_auth_segments[0] );

                return $wpo_auth_expiry < $token_expiry ? $wpo_auth_expiry : $token_expiry;
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
    }