<?php
    namespace Wpo\Aad;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Firebase\JWT\JWT;
    use \Wpo\Util\Error_Handler;
    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\User\User_Manager;

    if( !class_exists( '\Wpo\Aad\Auth' ) ) {
    
        class Auth {

            const USR_META_WPO365_AUTH          = 'WPO365_AUTH';
            const USR_META_WPO365_AUTH_CODE     = 'WPO365_AUTH_CODE';

            // Used by AAD v2.0
            const USR_META_REFRESH_TOKEN        = 'wpo_refresh_token';
            const USR_META_ACCESS_TOKEN         = 'wpo_access_token';

            // Used by AAD v1.0
            const USR_META_REFRESH_TOKEN_PREFIX = 'wpo_refresh_token_for_';
            const USR_META_ACCESS_TOKEN_PREFIX  = 'wpo_access_token_for_';

            /**
             * Validates each incoming request to see whether user prior to request
             * was authenicated by Microsoft Office 365 / Azure AD.
             *
             * @since   1.0
             *
             * @return  void 
             */
            public static function validate_current_session() {
                // Prerequisites
                Helpers::wpmu_copy_wpo365_options();
                Helpers::is_wpo365_configured( true );

                // Process incoming stuff
                self::process_openidconnect_error();
                self::process_openidconnect_token();

                // Should we skip authentication
                if( true === self::skip_authentication() ) 
                    return;
                
                // No? Then let's do it
                self::authenticate();
            }

            /**
             * Destroys any session and authenication artefacts and hooked up with wpo365_logout and should
             * therefore never be called directly to avoid endless loops etc.
             *
             * @since   1.0
             *
             * @return  void 
             */
            public static function destroy_session() {
                Logger::write_log( 
                    'DEBUG', 
                    'Destroying session ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) );
                delete_user_meta( get_current_user_id(), Auth::USR_META_WPO365_AUTH );
                delete_user_meta( get_current_user_id(), Auth::USR_META_WPO365_AUTH_CODE );
            }

            /**
             * Same as destroy_session but with redirect to login page (but only if the 
             * login page isn't the current page).
             *
             * @since   1.0
             * 
             * @param   string  $login_error_code   Error code that is added to the logout url as query string parameter.
             * @return  void
             */
            public static function goodbye( $login_error_code ) {
                if( strpos( 
                        strtolower( wp_login_url() ), 
                        strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) ) === false ) {
                            do_action( 'destroy_wpo365_session' );

                            wp_destroy_current_session();
                            wp_clear_auth_cookie();
                            wp_set_current_user( 0 );
                            unset($_COOKIE[AUTH_COOKIE]);
                            unset($_COOKIE[SECURE_AUTH_COOKIE]);
                            unset($_COOKIE[LOGGED_IN_COOKIE]);

                            $login_url = wp_login_url( '', true );
                            $login_url = add_query_arg( 'login_errors', $login_error_code, $login_url );
                            Helpers::force_redirect( $login_url );
                }
            }

            /**
             * Constructs the oauth authorize URL that is the end point where the user will be sent for authorization.
             * 
             * @since 4.0
             * 
             * @return string if everthing is configured OK a valid authorization URL
             */
            public static function get_oauth_url() {
                // Return the AAD v2.0 URL if configured so
                if( Helpers::get_global_boolean_var( 'WPO_USE_V2' ) )
                    return self::get_v2_oauth_url();
                
                // Global vars have been checked prior to this
                $redirect_url = Helpers::get_global_var( 'WPO_REDIRECT_URL' );

                $params = array( 
                    'client_id'     => Helpers::get_global_var( 'WPO_APPLICATION_ID' ),
                    'response_type' => 'id_token code',
                    'redirect_uri'  => $redirect_url,
                    'response_mode' => 'form_post',
                    'scope'         => 'openid',
                    'resource'      => Helpers::get_global_var( 'WPO_RESOURCE_azure_ad' ),
                    'state'         => ( strpos( $redirect_url, 'https' ) !== false ? 'https' : 'http' ) . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                    'nonce'         => Helpers::get_nonce(),
                );

                $directory_id = Helpers::get_global_var( 'WPO_DIRECTORY_ID' );

                $oauth_url = 'https://login.microsoftonline.com/' . $directory_id . '/oauth2/authorize?' . http_build_query( $params, '', '&' );
                return $oauth_url;
            }

            /**
             * Constructs the oauth authorize URL that is the end point where the user will be sent for authorization.
             * 
             * @since 6.1
             * 
             * @return string if everthing is configured OK a valid authorization URL
             */
            public static function get_v2_oauth_url() {
                // Global vars have been checked prior to this
                $redirect_url = Helpers::get_global_var( 'WPO_REDIRECT_URL' );

                $params = array( 
                    'client_id'     => Helpers::get_global_var( 'WPO_APPLICATION_ID' ),
                    'response_type' => 'id_token code',
                    'redirect_uri'  => $redirect_url,
                    'response_mode' => 'form_post',
                    'scope'         => 'openid email profile',
                    'state'         => ( strpos( $redirect_url, 'https' ) !== false ? 'https' : 'http' ) . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]",
                    'nonce'         => Helpers::get_nonce(),
                );

                $directory_id = Helpers::get_global_var( 'WPO_DIRECTORY_ID' );

                $oauth_url = 'https://login.microsoftonline.com/' . $directory_id . '/oauth2/v2.0/authorize?' . http_build_query( $params, '', '&' );
                return $oauth_url;
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

                $authorizeUrl = Auth::get_oauth_url();
                Logger::write_log( 'DEBUG', 'Getting fresh id and authorization tokens: ' . $authorizeUrl );

                // Redirect to Microsoft Authorization Endpoint
                Helpers::force_redirect(  $authorizeUrl );
            }

            /**
             * Handles redirect from Microsofts authorization service and tries to detect
             * any wrong doing and if detected redirects wrong-doer to Wordpress login instead
             *
             * @since   1.0
             * @return  void
             */
            public static function process_openidconnect_token() {
                if( false === isset( $_POST[ 'state' ] )
                    || false === isset( $_POST[ 'id_token' ] ) )
                        return;
                
                Logger::write_log( 'DEBUG', 'Processing incoming OpenID Connect id_token' );

                // Decode the id_token
                $id_token = Auth::decode_id_token();

                // Handle if token could not be processed or nonce is invalid
                if( $id_token === false 
                    || Helpers::validate_nonce( $id_token->nonce ) !== true ) {
                        Logger::write_log( 'ERROR', 'id token could not be processed and user will be redirected to default Wordpress login' );
                        Auth::goodbye( Error_Handler::TAMPERED_WITH );
                }

                // Log id token if configured
                if( true === Helpers::get_global_boolean_var( 'WPO_DEBUG_LOG_ID_TOKEN' ) )
                        Logger::write_log( 'DEBUG', $id_token );

                // Ensure user with the information found in the id_token
                $wp_usr = User_Manager::ensure_user( $id_token );
                
                // Handle if user could not be processed
                if( empty( $wp_usr ) ) {
                    Logger::write_log( 'ERROR', 'Could not get or create Wordpress user' );
                    Auth::goodbye( Error_Handler::USER_NOT_FOUND );
                }

                // Store the Authorization Code for extensions that may need it to obtain access codes for AAD secured resources
                if( isset( $_POST[ 'code' ] ) ) {
                    // Session valid until
                    $auth_code = new \stdClass();
                    $auth_code->expiry = time() + 3480;
                    $auth_code->code = $_POST[ 'code' ];

                    update_user_meta(
                        get_current_user_id(), 
                        Auth::USR_META_WPO365_AUTH_CODE, 
                        json_encode( $auth_code ) );
                }

                // @deprecated
                do_action( 'wpo365_openid_token_processed' );

                Logger::write_log( 'DEBUG', 'Redirecting to ' . $_POST[ 'state' ] );
                Helpers::force_redirect( $_POST[ 'state' ] );
            }

            private static function process_openidconnect_error() {
                if( isset( $_POST[ 'error' ] ) ) {
                    $error_string = $_POST[ 'error' ] . isset( $_POST[ 'error_description' ] ) ? $_POST[ 'error_description' ] : '';
                    Logger::write_log( 'ERROR', $error_string );
                    Auth::goodbye( Error_Handler::CHECK_LOG );
                }
            }

            /**
             * Unraffles the incoming JWT id_token with the help of Firebase\JWT and the tenant specific public keys available from Microsoft.
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
                $keys = Auth::discover_ms_public_keys( false );
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
                try {
                    $decoded_token = $jwt_decoder::decode( 
                        $id_token, 
                        $pem_string,
                        array( strtoupper( $header->alg ) )
                    );
                }
                catch( \Exception $e ) {
                    Logger::write_log( 'ERROR', 'Could not decode ID token: ' . $e->getMessage() );
                    return false;
                }

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
             * @return  mixed(stdClass|NULL)    Cached keys if found and valid otherwise fresh new keys.
             */
            private static function discover_ms_public_keys( $refresh ) {
                if( false === $refresh ) {
                    $cached_keys = get_site_option( 'wpo365_msft_keys' );

                    if( !empty( $cached_keys ) ) {
                        $cached_keys_segments = explode( ',', $cached_keys, 2 );

                        if( sizeof( $cached_keys_segments ) == 2 && intval( $cached_keys_segments[0] ) > time() ) {
                            $keys = json_decode( $cached_keys_segments[1] );
                            Logger::write_log( 'DEBUG', 'Found cached MSFT public keys to decrypt the JWT token' );

                            if( isset( $keys->keys ) )
                                return $keys->keys;

                            return $keys;
                        }
                    }
                }
                
                Logger::write_log( 'DEBUG', 'Retrieving fresh MSFT public keys to decrypt the JWT token' );
                $v2 = Helpers::get_global_boolean_var( 'WPO_USE_V2' ) 
                    ? '/v2.0' 
                    : '';
                $ms_keys_url = "https://login.microsoftonline.com/common/discovery$v2/keys";
                
                $curl = curl_init();
                curl_setopt( $curl, CURLOPT_URL, $ms_keys_url );
                curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );

                if( true === Helpers::get_global_boolean_var( 'WPO_SKIP_SSL_HOST_VERIFICATION' ) ) {
                        curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                        curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 
                }

                $result = curl_exec( $curl ); // result holds the keys
                if( curl_error( $curl ) ) {
                    Logger::write_log( 'ERROR', 'error occured whilst getting msft decryption keys: ' . curl_error( $curl ) );
                    curl_close( $curl );
                    return NULL;
                }
                
                curl_close( $curl );
                update_site_option( 'wpo365_msft_keys', strval( time() + 21600 ) . ',' . $result );
                $keys = json_decode( $result );

                if( isset( $keys->keys ) )
                    return $keys->keys;
                
                return $keys;
            }
        
            /**
             * Retrieves the ( previously discovered ) public keys Microsoft used to encode the id_token
             *
             * @since   1.0
             *
             * @param   string  key-id to retrieve the matching keys
             * @param   array   keys previously discovered
             * @param   boolean whether or not to 
             * @return  void 
             */
            private static function retrieve_ms_public_key( $kid, $keys, $allow_refresh = true ) {
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

                if( true === $allow_refresh ) {
                    $new_keys = self::discover_ms_public_keys( true ); // Keys not found so lets refresh the cache
                    return self::retrieve_ms_public_key( $kid, $new_keys, false );
                }
 
                return false;
            }

            /**
             * Gets an access token in exchange for an authorization token that was received prior when getting
             * an OpenId Connect token or for a fresh code in case available
             *
             * @since   6.0
             *
             * @return mixed(stdClass|WP_Error) access token 
             */
            public static function get_bearer_token( $resource_uri ) {

                Logger::write_log( 'DEBUG', 'GET BEARER TOKEN' );

                // Don't even start if the user is not logged in
                if( !is_user_logged_in() )
                    return new \WP_Error( '1000', 'Cannot retrieve a bearer token for a user that is not logged in' );

                // Get resource nice name e.g. https://graph.microsoft.com => graph.microsoft.com
                $resource = self::get_resource_name_from_id( $resource_uri );

                if( is_wp_error( $resource ) )
                    return new \WP_Error( '1010', $resource->get_error_message() );

                // Tokens are stored by default as user metadata
                $cached_access_token_key = Auth::USR_META_ACCESS_TOKEN_PREFIX . $resource;
                $cached_access_token_json = get_user_meta( 
                    get_current_user_id(), 
                    $cached_access_token_key, 
                    true );
                
                
                if( !empty( $cached_access_token_json ) ) {
                    $access_token = json_decode( $cached_access_token_json );

                    // json_decode returns NULL if an "old" token is found
                    if( empty ($access_token ) || ( isset( $access_token->expiry ) && $access_token->expiry < time() ) )
                        delete_user_meta( get_current_user_id(), $cached_access_token_key );
                    else {
                        Logger::write_log( 'DEBUG', 'Found a previously saved access token that is still valid' );
                        Logger::write_log( 'DEBUG', $access_token );
                        return $access_token;
                    }
                }

                $params = array(
                    'client_id' => Helpers::get_global_var( 'WPO_APPLICATION_ID' ),
                    'client_secret' => Helpers::get_global_var( 'WPO_APPLICATION_SECRET' ),
                    'redirect_uri' => Helpers::get_global_var( 'WPO_REDIRECT_URL' ),
                    'resource' => $resource_uri,
                );

                // Check if we have a refresh token and if not fallback to the auth code
                $refresh_token = self::get_refresh_token();

                if( !empty( $refresh_token) ) {
                    $params[ 'grant_type' ] = 'refresh_token';
                    $params[ 'refresh_token' ] = $refresh_token->refresh_token;
                }
                else {
                    $auth_code = self::get_auth_code();
                    
                    if( !empty( $auth_code ) ) {
                        $params[ 'grant_type' ] = 'authorization_code';
                        $params[ 'code' ] = $auth_code->code;
                        // Delete the code since it can only be used once
                        delete_user_meta( get_current_user_id(), Auth::USR_META_WPO365_AUTH_CODE );
                    }
                }

                if( !isset( $params[ 'grant_type' ] ) ) {
                    $error_message = 'No authorization code and refresh token found when trying to get an access token for ' . $resource . ' (Send a new interactive authorization for this user and resource).';
                    Logger::write_log( 'ERROR', $error_message );
                    return new \WP_Error( '1030', $error_message );
                }

                Logger::write_log( 'DEBUG', 'Requesting access token for ' . $resource . ' using ' . $resource_uri );
                
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

                if( true === Helpers::get_global_boolean_var( 'WPO_SKIP_SSL_HOST_VERIFICATION' ) ) {
                        Logger::write_log( 'DEBUG', 'Skipping SSL peer and host verification' );

                        curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                        curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 
                }
            
                $result = curl_exec( $curl ); // result holds the tokens
            
                if( curl_error( $curl ) ) {
                    $error_message = 'Error occured whilst getting an access token';
                    Logger::write_log( 'ERROR', $error_message );
                    curl_close( $curl );

                    return new \WP_Error( '1040', curl_error( $curl ) );
                }
            
                curl_close( $curl );

                // Validate the access token and return it
                $access_token = json_decode( $result );
                $access_token = Auth::validate_bearer_token( $access_token );

                if( is_wp_error( $access_token ) ) {
                    Logger::write_log( 'ERROR', 'Access token for ' . $resource . ' appears to be invalid' );
                    return new \WP_Error( $access_token->get_error_code(), $access_token->get_error_message() );
                }

                // Store the new token as user meta with the shorter ttl of both auth and token
                $access_token->expiry = time() + intval( $access_token->expires_in );
                update_user_meta(
                    get_current_user_id(), 
                    $cached_access_token_key, 
                    json_encode( $access_token ) );

                // Save refresh token
                if( isset( $access_token->refresh_token ) )
                    Auth::set_refresh_token( $access_token );

                Logger::write_log( 'DEBUG', 'Successfully obtained a valid access token for ' . $resource );
                Logger::write_log( 'DEBUG', $access_token );

                return $access_token;
            }

            /**
             * Gets an access token in exchange for an authorization token that was received prior when getting
             * an OpenId Connect token or for a fresh code in case available. This method is only compatible with 
             * AAD v2.0
             *
             * @since 6.1
             * 
             * @param $scope string Scope for AAD v2.0 e.g. https://graph.microsoft.com/user.read
             *
             * @return mixed(stdClass|WP_Error) access token as object or WP_Error
             */
            public static function get_bearer_token_v2( $scope ) {

                Logger::write_log( 'DEBUG', 'GET BEARER TOKEN V2' );

                // Don't even start if the user is not logged in
                if( !is_user_logged_in() )
                    return new \WP_Error( '1000', 'Cannot retrieve a bearer token for a user that is not logged in' );
                
                // Tokens are stored by default as user metadata
                $cached_access_token_json = get_user_meta( 
                    get_current_user_id(), 
                    self::USR_META_ACCESS_TOKEN, 
                    true );
                
                // Valid access token was saved previously
                if( !empty( $cached_access_token_json ) ) {
                    $access_token = json_decode( $cached_access_token_json );
                    Logger::write_log( 'DEBUG', 'Found a previously saved access token' );
                    Logger::write_log( 'DEBUG', $access_token );
                    
                    if( isset( $access_token->expiry ) && intval( $access_token->expiry ) < time() )
                        delete_user_meta( get_current_user_id(), self::USR_META_ACCESS_TOKEN );
                    elseif( isset( $access_token->scope ) && false !== strpos( strtolower( $access_token->scope ), $scope ) ) {
                        Logger::write_log( 'DEBUG', 'Found a previously saved access token that is still valid' );
                        return $access_token;
                    }
                }

                $params = array(
                    'client_id' => Helpers::get_global_var( 'WPO_APPLICATION_ID' ),
                    'client_secret' => Helpers::get_global_var( 'WPO_APPLICATION_SECRET' ),
                    'redirect_uri' => Helpers::get_global_var( 'WPO_REDIRECT_URL' ),
                    'scope' => 'offline_access ' . $scope, // Request offline_access to get a refresh token
                );

                // Check if we have a refresh token and if not fallback to the auth code
                $refresh_token = Auth::get_refresh_token();

                if( !empty( $refresh_token) ) {
                    $params[ 'grant_type' ] = 'refresh_token';
                    $params[ 'refresh_token' ] = $refresh_token->refresh_token;
                }
                else {
                    $auth_code = self::get_auth_code();

                    if( !empty( $auth_code ) ) {
                        $params[ 'grant_type' ] = 'authorization_code';
                        $params[ 'code' ] = $auth_code->code;
                        // Delete the code since it can only be used once
                        delete_user_meta( get_current_user_id(), Auth::USR_META_WPO365_AUTH_CODE );
                    }
                }

                if( !isset( $params[ 'grant_type' ] ) ) {
                    $error_message = 'No authorization code and refresh token found when trying to get an access token for ' . $resource . ' (Send a new interactive authorization for this user and resource).';
                    Logger::write_log( 'ERROR', $error_message );
                    return new \WP_Error( '1030', $error_message );
                }

                Logger::write_log( 'DEBUG', 'Requesting access token for ' . $scope );
                
                $params_as_str = http_build_query( $params, '', '&' ); // Fix encoding of ampersand
                $authorizeUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
                
                $curl = curl_init();
                curl_setopt( $curl, CURLOPT_POST, 1 );
                curl_setopt( $curl, CURLOPT_URL, $authorizeUrl );
                curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );
                curl_setopt( $curl, CURLOPT_POSTFIELDS, $params_as_str );
                curl_setopt( $curl, CURLOPT_HTTPHEADER, array( 
                    'Content-Type: application/x-www-form-urlencoded'
                ) );

                if( true === Helpers::get_global_boolean_var( 'WPO_SKIP_SSL_HOST_VERIFICATION' ) ) {
                    
                    Logger::write_log( 'DEBUG', 'Skipping SSL peer and host verification' );
                    curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                    curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 
                }
            
                $result = curl_exec( $curl ); // result holds the tokens
            
                if( curl_error( $curl ) ) {
                    $error_message = 'Error occured whilst getting an access token';
                    Logger::write_log( 'ERROR', $error_message );
                    curl_close( $curl );

                    return new \WP_Error( '1040', curl_error( $curl ) );
                }
            
                curl_close( $curl );

                // Validate the access token and return it
                $access_token = json_decode( $result );
                $access_token = Auth::validate_bearer_token( $access_token );

                if( is_wp_error( $access_token ) ) {
                    Logger::write_log( 'ERROR', 'Access token for ' . $scope . ' appears to be invalid' );
                    return new \WP_Error( $access_token->get_error_code(), $access_token->get_error_message() );
                }

                // Store the new token as user meta with the shorter ttl of both auth and token
                $access_token->expiry = time() + intval( $access_token->expires_in );
                update_user_meta( 
                    get_current_user_id(), 
                    self::USR_META_ACCESS_TOKEN, 
                    json_encode( $access_token ) );

                // Save refresh token
                if( isset( $access_token->refresh_token ) )
                    Auth::set_refresh_token( $access_token );
                
                Logger::write_log( 'DEBUG', 'Successfully obtained a valid access token for ' . $scope );
                Logger::write_log( 'DEBUG', $access_token );

                return $access_token;
            }

            /**
             * Helper to validate an oauth access token
             *
             * @since   6.0
             *
             * @param   object  access token as PHP std object
             * @return  mixed(stdClass|WP_Error) Access token as standard object or WP_Error when invalid   
             * @todo    Improve by verifying against requested scope
             */
            private static function validate_bearer_token( $access_token_obj ) {

                if( isset( $access_token_obj->error ) ) {

                    Logger::write_log( 'ERROR', 'Error found whilst validating access token: ' . $access_token_obj->error_description );
                    return new \WP_Error( implode( ',', $access_token_obj->error_codes), $access_token_obj->error_description );
                }
            
                if( empty( $access_token_obj ) 
                    || $access_token_obj === false
                    || !isset( $access_token_obj->access_token ) 
                    || !isset( $access_token_obj->expires_in ) 
                    || !isset( $access_token_obj->token_type )
                    || !isset( $access_token_obj->scope )
                    || strtolower( $access_token_obj->token_type ) != 'bearer' ) {
            
                    Logger::write_log( 'ERROR', 'Incomplete access code detected' );
                    return new \WP_Error( '0', 'Unknown error occurred' );
                }
            
                return $access_token_obj;
            }

            /**
             * Tries and find a refresh token for an AAD resource stored as user meta in the form "expiration,token"
             * In case an expired token is found it will be deleted
             *
             * @since   5.1
             * 
             * @param   string  $resource   Name for the resource key used to store that resource in the site options
             * @return  (stdClass|NULL)  Refresh token or an empty string if not found or when expired
             */
            private static function get_refresh_token() {
                $cached_refresh_token_json = get_user_meta( 
                    get_current_user_id(),
                    Auth::USR_META_REFRESH_TOKEN,
                    true );
                
                if( empty( $cached_refresh_token_json ) )
                    return NULL;
                
                $refresh_token = json_decode( $cached_refresh_token_json );
                Logger::write_log( 'DEBUG', 'Found a previously saved refresh token' );
                
                if( isset( $refresh_token->expiry ) && intval( $refresh_token->expiry ) < time() )
                    delete_user_meta( get_current_user_id(), Auth::USR_META_REFRESH_TOKEN );
                else {
                    Logger::write_log( 'DEBUG', 'Found a previously saved valid refresh token' );
                    return $refresh_token;
                }
                
                Logger::write_log( 'DEBUG', 'Could not find a valid refresh token' );
                return NULL;
            }

            /**
             * Helper method to persist a refresh token as user meta.
             * 
             * @since 5.1
             * 
             * @param stdClass $access_token Access token as standard object (from json)
             * @return void
             */
            private static function set_refresh_token( $access_token ) {

                $refresh_token = new \stdClass();
                $refresh_token->refresh_token = $access_token->refresh_token;
                $refresh_token->scope = $access_token->scope;
                $refresh_token->expiry = time( ) + 1209600;
                
                update_user_meta( 
                    get_current_user_id(),
                    self::USR_META_REFRESH_TOKEN,
                    json_encode( $refresh_token ) );

                Logger::write_log( 'DEBUG', 'Successfully stored refresh token' );
            }

            /**
             * Tries and find an authorization code stored as user meta
             * In case an expired token is found it will be deleted
             * 
             * @since 5.2
             * 
             * @return (stdClass|NULL)
             */
            private static function get_auth_code() {
                $auth_code_value = get_user_meta( 
                    get_current_user_id(),
                    Auth::USR_META_WPO365_AUTH_CODE,
                    true );
                
                if( empty( $auth_code_value ) ) 
                    return NULL;

                $auth_code = json_decode( $auth_code_value );
                
                if( empty( $auth_code ) )
                    return NULL;

                if( isset( $auth_code->expiry ) && intval( $auth_code->expiry ) < time() )
                    delete_user_meta( get_current_user_id(), Auth::USR_META_WPO365_AUTH_CODE );
                else
                    return $auth_code;
                return NULL;
            }

            /**
             * Retrieves the sub domain part of a Resource URI e.g. graph for https://graph.microsoft.com
             * 
             * @since 6.0
             * 
             * @param $resource_uri string e.g. https://yourtenant.sharepoint.com
             * 
             * @return mixed(string|WP_Error)
             */
            public static function get_resource_name_from_id( $resource_uri ) {
 
                if( strpos( $resource_uri, 'http' ) !== 0 )
                    return new \WP_Error( '2000', 'Resource ID must start with http(s)' );

                $resource_uri_segments = explode( '/', $resource_uri );

                if( sizeof( $resource_uri_segments ) >= 3 )
                    return $resource_uri_segments[2];

                return new \WP_Error( '2010', 'Resource ID not formatted as URI' );
            }

            
            /**
             * Checks the configured scenario and the pages black list settings to
             * decide whether or not authentication of the current page is needed.
             * 
             * @since 6.0
             * 
             * @return  boolean     True if validation should be skipped, otherwise false.
             */
            private static function skip_authentication() {
                $scenario = Helpers::get_global_var( 'WPO_AUTH_SCENARIO' );

                if( !is_admin() && !is_wp_error( $scenario ) && $scenario == 2 ) {
                        Logger::write_log( 'DEBUG', 'Cancelling session validation for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) . ' because selected scenario is \'Internet\'' );
                        return true;
                }
                
                Logger::write_log( 'DEBUG', 'Validating session for page ' . strtolower( basename( $_SERVER[ 'PHP_SELF' ] ) ) );
                
                // Check if current page is blacklisted and can be skipped
                $black_listed_pages = Helpers::get_global_var( 'WPO_PAGES_BLACKLIST' );
                Logger::write_log( 'DEBUG', 'Validating session for path ' . strtolower( $_SERVER[ 'REQUEST_URI' ] ) );
                
                // Check if current page is blacklisted and can be skipped
                if( !is_wp_error( $black_listed_pages ) ) {

                        $black_listed_pages = explode( ';', strtolower( trim( $black_listed_pages ) ) );
                        $request_uri = strtolower( $_SERVER[ 'REQUEST_URI' ] );

                        foreach( $black_listed_pages as $black_listed_page ) {

                            if( empty( $black_listed_page ) )
                                continue;
                            
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
                                return true;
                            }
                        }
                }
                
                return false;
            }
            
            /**
             * Checks for an existing and not yet expired authorization flag and
             * if not found starts the Sign in with Microsoft authentication flow 
             * by redirecting the user to Microsoft's IDP.
             * 
             * @since 6.0
             * 
             * @return void
             */
            private static function authenticate() {
                $wpo_auth_value = get_user_meta(
                    get_current_user_id(),
                    Auth::USR_META_WPO365_AUTH,
                    true );

                // Logged-on WP-only user
                if( is_user_logged_in() && empty( $wpo_auth_value ) ) {
                    Logger::write_log( 'DEBUG', 'User is a Wordpress-only user so no authentication is required' );
                    return;
                }
                
                // User not logged on
                if( empty( $wpo_auth_value ) ) {                    
                    Auth::get_openidconnect_and_oauth_token();
                    return;
                }

                // Check if user has expired 
                $wpo_auth = json_decode( $wpo_auth_value );
                if( !isset( $wpo_auth->expiry ) || $wpo_auth->expiry < time() ) {
                    do_action( 'destroy_wpo365_session' );
                
                    // Don't call wp_logout because it may be extended
                    wp_destroy_current_session();
                    wp_clear_auth_cookie();
                    wp_set_current_user( 0 );
                    unset($_COOKIE[AUTH_COOKIE]);
                    unset($_COOKIE[SECURE_AUTH_COOKIE]);
                    unset($_COOKIE[LOGGED_IN_COOKIE]);

                    Logger::write_log( 'DEBUG', 'User logged out because current login not valid anymore' );
                    Auth::get_openidconnect_and_oauth_token();
                    return;
                }
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
?>