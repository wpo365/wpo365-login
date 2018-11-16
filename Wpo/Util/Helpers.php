<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Util\Logger;
    use \Wpo\Aad\Auth;
    use \Wpo\Util\Error_Handler;

    if( !class_exists( '\Wpo\Util\Helpers' ) ) {

        class Helpers {

            /**
             * Checks whether headers are sent before trying to redirect and if sent falls
             * back to an alternative method
             * 
             * @since 4.3
             * 
             * @param string $url URL to redirect to
             * @return void
             */
            public static function force_redirect( $url ) {

                if( headers_sent() ) {
                    Logger::write_log( 'DEBUG', 'Headers sent when trying to redirect user to ' . $url );
                    echo '<script type="text/javascript">';
                    echo 'window.location.href="'. $url . '";';
                    echo '</script>';
                    echo '<noscript>';
                    echo '<meta http-equiv="refresh" content="0;url=' . $url . '" />';
                    echo '</noscript>';
                    exit();
                }

                wp_redirect( $url );
                exit();
            }
            
            /**
             * Helper method to ensure that short codes are initialized
             * 
             * @since 4.0
             * 
             * @return void
             */
            public static function ensure_short_codes() {

                if( !shortcode_exists( 'pintra' ) )
                    add_shortcode( 'pintra', '\Wpo\Util\Helpers::add_pintra_shortcode' );
            }

            /**
             * Adds the Search Center short code that injects the Search Center template 
             * 
             * @since 4.7
             * 
             * @param array short code parameters according to Wordpress codex
             * @param string content found in between the short code start and end tag
             * @param string text domain
             */
            public static function add_pintra_shortcode( $atts = array(), $content = null, $tag = '' ) {
                $atts = array_change_key_case( (array)$atts, CASE_LOWER);
                $props = '[]';
                
                if( isset( $atts[ 'props' ] ) 
                    && strlen( trim( $atts[ 'props' ] ) ) > 0 ) {
                        $result = array();
                        $prop_kv_pairs = explode( ';', $atts[ 'props' ] );
                        
                        foreach( $prop_kv_pairs as  $prop_kv_pair ) {
                            $prop_kv_array = explode( ',', $prop_kv_pair );
                            
                            if( sizeof( $prop_kv_array ) == 2)
                                $result[ $prop_kv_array[0] ] = addslashes( utf8_encode( $prop_kv_array[1] ) );
                        }
                        $props = json_encode( $result );
                }

                $script_url = isset( $atts[ 'script_url' ] ) ? $atts[ 'script_url' ] : '';

                ob_start();
                include( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/templates/pintra.php' );
                $content = ob_get_clean();
                return $content;
            }

            /**
             * When multisite and when using Redux then try and obtain settings from the main site 
             * in the network
             * 
             * @since 4.7
             * 
             * @return void
             */
            public static function wpmu_copy_wpo365_options() {
                if( is_multisite() && defined( 'WPO_USE_WP_CONFIG' ) && constant( 'WPO_USE_WP_CONFIG' ) !== true ) {
                    
                    global $current_site;
                    $main_site_blog_id = (int)$current_site->blog_id;
                    
                    if( get_option( 'wpo365_options' ) != get_blog_option( $main_site_blog_id, 'wpo365_options' ) ) 
                        update_option( 'wpo365_options', get_blog_option( 1, 'wpo365_options' ) );
                }
            }

            /**
             * Checks whether the mandatory fields have been configured once the
             * plugin is activate
             * 
             * @since 4.7
             * 
             * @param $exit boolean True if the user should be sent to the login form, otherwise false.
             * 
             * @return boolean True if minimal set of options have been configured.
             */
            public static function is_wpo365_configured( $exit ) {
                $directory_id = self::get_global_var( 'WPO_DIRECTORY_ID' );
                $application_id = self::get_global_var( 'WPO_APPLICATION_ID' );
                $redirect_url = self::get_global_var( 'WPO_REDIRECT_URL' );
                $scope = self::get_global_var( 'WPO_SCOPE' );
                $resource = self::get_global_var( 'WPO_RESOURCE_azure_ad' );

                // Check if WPO365 is unconfigured and if so redirect to login page
                if( ( is_wp_error( $directory_id ) 
                    || is_wp_error( $application_id ) 
                    || is_wp_error( $redirect_url )
                    || is_wp_error( $scope )
                    || is_wp_error( $resource ) ) ) {
                        Logger::write_log( 'ERROR', 'WPO365 not configured' );

                        // Only prevent O365 users from logging in
                        if( $exit && !is_user_logged_in() ) 
                            Auth::goodbye( Error_Handler::NOT_CONFIGURED );
                        else 
                            return false;
                }

                return true;
            }
            
            /**
             * Gets the domain (host) part of an email address.
             * 
             * @since 3.1
             * 
             * @param   string  $email_address  email address to analyze
             * @return  string  Returns the email address' host part or an empty string if
             *                  the email address appears to be invalid
             */
            public static function get_smtp_domain_from_email_address( $email_address ) {
                $smpt_domain = '';
                if( filter_var( trim( $email_address ), FILTER_VALIDATE_EMAIL ) !== false )
                    $smpt_domain = strtolower( trim( substr( $email_address, strrpos( $email_address, '@' )  + 1 ) ) );

                return $smpt_domain;
            }

            /**
             * Checks a user's smtp domain against the configured custom and default domains
             * 
             * @since 4.0
             * 
             * @return boolean true if a match is found otherwise false
             */
            public static function is_tenant_domain( $email_domain ) {
                $custom_domain = self::get_global_var( 'WPO_CUSTOM_DOMAIN' );
                $default_domain = self::get_global_var( 'WPO_DEFAULT_DOMAIN' );

                if( !is_wp_error( $custom_domain ) && false !== strpos( $custom_domain, ";" )) {
                    $custom_domains = explode( ";", trim( $custom_domain ) );
                    $custom_domain = array_flip( $custom_domains );
                }

                if( ( 
                    !is_wp_error( $custom_domain ) && ( ( is_array( $custom_domain ) && array_key_exists( $email_domain, $custom_domain ) ) 
                    || ( !is_array( $custom_domain ) && strtolower( trim( $custom_domain ) ) == $email_domain ) ) )
                    || ( !is_wp_error( $default_domain ) && strtolower( trim( $default_domain ) ) == $email_domain ) )
                        return true;
                
                return false;
            }

            /**
             * Creates a nonce using the nonce_secret
             * 
             * @since 1.6
             * 
             * @return (string|WP_Error) nonce as a string otherwise an WP_Error (most likely when dependency are missing)
             */
            public static function get_nonce() {

                $nonce_salt = constant( 'NONCE_SALT' );
                
                if( empty( $nonce_salt ) ) {

                    Logger::write_log( 'ERROR', 'Global var NONCE_SALT not defined' );
                    return new \WP_Error( '4000', 'Nonce salt not defined' );
                }

                $nonce_secret = $nonce_salt;

                if( isset( $GLOBALS['wpo365_options'] ) && isset( $GLOBALS['wpo365_options']['nonce_secret'] ) ) {

                    $nonce_secret = $GLOBALS['wpo365_options']['nonce_secret'];
                }

                $nonce_hash = hash_hmac( 'sha256', $nonce_secret, $nonce_salt, false );

                $expires = time() + 300; // expires 5 minutes from now

                return base64_encode( 
                    json_encode( 
                        array(
                            'nonce' => $nonce_hash,
                            'expires' => $expires,
                        ) 
                    ) 
                );

            }

            /**
             * Validates a nonce created with Helpers::get_nonce()
             * 
             * @since 1.6
             * 
             * @param string $nonce encoded nonce value to validate
             * @return (boolean|WP_Error) true when valide otherwise WP_Error
             */
            public static function validate_nonce( $nonce ) {

                $nonce_salt = constant( 'NONCE_SALT' );

                if( empty( $nonce_salt ) ) {

                    Logger::write_log( 'ERROR', 'Global var NONCE_SALT not defined' );
                    return new \WP_Error( '5000', 'Nonce salt not defined' );
                }

                $nonce_secret = $nonce_salt;

                if( isset( $GLOBALS['wpo365_options'] ) && isset( $GLOBALS['wpo365_options']['nonce_secret'] ) ) {

                    $nonce_secret = $GLOBALS['wpo365_options']['nonce_secret'];
                }

                $decoded = base64_decode( $nonce );

                if ($decoded === false) {
                
                    Logger::write_log( 'ERROR', 'Your login has been tampered with [decoding failed]' );
                    return new \WP_Error( '5010', 'Your login has been tampered with [decoding failed]' );
                }

                $message = json_decode( $decoded );
                $nonce_hash = hash_hmac( 'sha256', $nonce_secret, $nonce_salt, false );

                if( $message->nonce != $nonce_hash ) {

                    Logger::write_log( 'ERROR', 'Your login has been tampered with [hash does not match]' );
                    return new \WP_Error( '5020', 'Your login has been tampered with [hash does not match]' );
                }

                if ( time() > intval( $message->expires ) ) {
                    
                    Logger::write_log( 'ERROR', 'Your login has been tampered with [nonce expired]' );
                    return new \WP_Error( '5030', 'Your login has been tampered with [nonce expired]' );
                }

                Logger::write_log( 'DEBUG', 'Nonce message: ' . $message->nonce );
                return true;

            }

            /**
             * Analyzes url and tries to discover site details for both single and multisite WP networks
             *
             * @since   3.0
             * @param   string    target $url of the site to analyze (can point to a post, a subsite etc.)
             * @return  array     associative array with blog id, site url, network url, multisite y/n etc.
             */
            public static function target_site_info( $url ) {

                // Ensure url starts with protocol
                if( strpos( $url, 'http' ) !== 0 ) {

                    return null;
                }

                // Multisite has dependencies that are only loaded when needed
                if( is_multisite() ) {
                    
                    return self::ms_target_site_info( $url );
                }

                // Not multisite
                $site_url = site_url();

                $segments = explode( '/', $site_url );
                $nr_of_segments = sizeof( $segments );

                $protocol = str_replace( ':', '', $segments[ 0 ] );
                $domain = $segments[ 2 ];
                $path = $nr_of_segments == 3 ? '/' : ('/' . implode( '/', array_slice( $segments, 3, $nr_of_segments - 3 ) ) . '/' );
                $blogid = get_current_blog_id(); // may be 0 for main site but this may not be target site 
                
                return array(

                    'blog_id'                    => $blogid, // always 1
                    'protocol'                   => $protocol,
                    'domain'                     => $domain,
                    'path'                       => $path,
                    'is_multi'                   => false,
                    'target_site_url'            => $site_url,
                    'network_site_url'           => $site_url,
                    'target_is_network_site'     => true,
                    'subdomain_install'          => false,
                );
            }

            /**
             * Analyzes url and tries to discover site details for both single and multisite WP networks (private, use
             * target_site_info() instead)
             *
             * @since   3.0
             * @param   string    target $url of the site to analyze (can point to a post, a subsite etc.)
             * @return  array     associative array with blog id, site url, network url, multisite y/n etc.
             */
            private static function ms_target_site_info( $url ) {

                $network_site_url = network_site_url(); // if not multisite site_url() is used

                $segments = explode( '/', $url );
                $nr_of_segments = sizeof( $segments );

                if( $nr_of_segments < 3 ) {

                    return false;                    
                }

                $protocol = str_replace( ':', '', $segments[ 0 ] );
                $domain = $segments[ 2 ];
                $path = '/';
                $blogid = get_blog_id_from_url( $domain ); // may be 0 for main site but this may not be target site
                $subdomain_install = get_site_option( 'subdomain_install' );

                if( $nr_of_segments > 3 ) {

                    for( $i = 3; $i < $nr_of_segments; $i++ ) {

                        $path_test = '/' . implode( '/', array_slice( $segments, 3, $nr_of_segments - $i ) ) . '/';
                        $blog_id_test = get_blog_id_from_url( $domain, $path_test );
                        
                        if( $blog_id_test > 0 ) {

                            $blogid = $blog_id_test;
                            $path = $path_test;
                            break;
                        }
                    }
                }
                
                return array(

                    'blog_id'                    => $blogid,
                    'protocol'                   => $protocol,
                    'domain'                     => $domain,
                    'path'                       => $path,
                    'is_multi'                   => true,
                    'target_site_url'            => ( $protocol . '://' . $domain . $path ),
                    'network_site_url'           => $network_site_url,
                    'target_is_network_site'     => ( $protocol . '://' . $domain . $path == $network_site_url ),
                    'subdomain_install'          => $subdomain_install,
                );
            }

            /**
             * Adds custom wp query vars
             * 
             * @since 3.6
             * 
             * @param Array $vars existing wp query vars
             * @return Array updated $vars that now includes custom wp query vars
             */
            public static function add_query_vars_filter( $vars ) {

                $vars[] = 'login_errors';
                return $vars;
            }

            /**
             * Removes query string from string ( there may be an incompatibility with URL rewrite )
             *
             * @since 3.0
             *
             * @return  Current URL as string without query string
             */
            public static function check_version() {

                // Get plugin version from db
                $plugin_db_version = get_site_option( 'wpo365-login-version' );

                // Add new option if not yet existing
                if( false === $plugin_db_version ) {

                    update_site_option( 'wpo365-login-version', $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] );
                    self::track( 'install' );
                    return;

                }
                // Compare plugin version with db version and track in case of update
                elseif( $plugin_db_version != $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] ) {

                    update_site_option( 'wpo365-login-version', $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] );
                    self::track( 'update' );
                }
            }

            /**
             * Removes query string from string ( there may be an incompatibility with URL rewrite )
             *
             * @since 3.0
             *
             * @param   string  Name of event to track (default is install)
             * @return  Current URL as string without query string
             */
            public static function track( $event ) {

                $plugin_version = $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ];
                $event .= '_login';

                $ga = "https://www.google-analytics.com/collect?v=1&tid=UA-5623266-11&aip=1&cid=bb923bfc-cae8-11e7-abc4-cec278b6b50a&t=event&ec=alm&ea=$event&el=$plugin_version";

                $curl = curl_init();

                curl_setopt( $curl, CURLOPT_URL, $ga );
                curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );

                curl_setopt( $curl, CURLOPT_SSL_VERIFYPEER, 0 ); 
                curl_setopt( $curl, CURLOPT_SSL_VERIFYHOST, 0 ); 
                
                $result = curl_exec( $curl ); // result holds the keys
                if( curl_error( $curl ) ) {
                    
                    // TODO handle error
                    Logger::write_log( 'ERROR', 'error occured whilst tracking an alm event: ' . curl_error( $curl ) );

                }
                curl_close( $curl );
            }

            /**
             * Gets a global variable by its name and depending on global configuration expects this variable
             * to be a redux managed option or a manually setup global wp-config.php variable.
             * 
             * @param   string  $name   Variable name as string
             * @return  object|WP_Error The global variable or WP_Error if not found
             */
            public static function get_global_var( $name ) {                
                $redux_keys = array(
                    // application_name has been deprecated
                    'WPO_CUSTOM_DOMAIN'                 => 'custom_domain',
                    'WPO_DEFAULT_DOMAIN'                => 'default_domain',
                    'WPO_DIRECTORY_ID'                  => 'tenant_id',
                    'WPO_APPLICATION_ID'                => 'application_id',
                    'WPO_RESOURCE_azure_ad'             => 'aad_resource_uri',
                    'WPO_APP_ID_URI'                    => 'application_uri',
                    'WPO_APPLICATION_SECRET'            => 'application_secret',
                    'WPO_SCOPE'                         => 'scope',
                    'WPO_REDIRECT_URL'                  => 'redirect_url',
                    'WPO_NONCE_SECRET'                  => 'nonce_secret',
                    'WPO_GOTO_AFTER_SIGNON_URL'         => 'goto_after_signon_url',
                    'WPO_PAGES_BLACKLIST'               => 'pages_blacklist',
                    'WPO_DOMAIN_WHITELIST'              => 'domain_whitelist',
                    'WPO_SESSION_DURATION'              => 'session_duration',
                    'WPO_REFRESH_DURATION'              => 'refresh_duration',
                    'WPO_BLOCK_EMAIL_UPDATE'            => 'block_email_change',
                    'WPO_BLOCK_PASSWORD_UPDATE'         => 'block_password_change',
                    'WPO_AUTH_SCENARIO'                 => 'auth_scenario',
                    'WPO_CREATE_ADD_USERS'              => 'create_and_add_users',
                    'WPO_DEFAULT_ROLE_MAIN_SITE'        => 'new_usr_default_role',
                    'WPO_DEFAULT_ROLE_SUB_SITE'         => 'mu_new_usr_default_role',
                    'WPO_SKIP_SSL_HOST_VERIFICATION'    => 'skip_host_verification',
                    'WPO_DEBUG_LOG_ID_TOKEN'            => 'debug_log_id_token',
                    'WPO_MAIL_MIME_TYPE'                => 'mail_mime_type',
                    'WPO_MAIL_SAVE_TO_SENT'             => 'mail_save_on_sent',
                    'WPO_LEEWAY'                        => 'leeway',
                    'WPO_ALWAYS_USE_GOTO_AFTER'         => 'always_use_goto_after',
                    'WPO_ENABLE_TOKEN_SERVICE'          => 'enable_token_service',
                    'WPO_ENABLE_NONCE_CHECK'            => 'enable_nonce_check',
                    'WPO_ERROR_NOT_CONFIGURED'          => 'WPO_ERROR_NOT_CONFIGURED',
                    'WPO_ERROR_CHECK_LOG'               => 'WPO_ERROR_CHECK_LOG',
                    'WPO_ERROR_TAMPERED_WITH'           => 'WPO_ERROR_TAMPERED_WITH',
                    'WPO_ERROR_USER_NOT_FOUND'          => 'WPO_ERROR_USER_NOT_FOUND',
                    'WPO_ERROR_NOT_IN_GROUP'            => 'WPO_ERROR_NOT_IN_GROUP',
                );

                if( empty( $redux_keys[ $name ] ) ) {

                    Logger::write_log( 'DEBUG', "Could not find the variable with name $name in the redux to wp-config.php mapping table." );
                    return new \WP_Error( '3020', "Could not find the variable with name $name in the redux to wp-config.php mapping table." );
                }

                if( isset( $GLOBALS[ 'wpo365_options' ] ) 
                    && isset( $GLOBALS[ 'wpo365_options' ][ $redux_keys[ $name ] ] ) 
                    && !empty( $GLOBALS[ 'wpo365_options' ][ $redux_keys[ $name ] ] ) ) {

                        return $GLOBALS[ 'wpo365_options' ][ $redux_keys[ $name ] ];
                }

                Logger::write_log( 'DEBUG', "Whilst falling back to redux options a global variable with name $name is not properly configured." );
                return new \WP_Error( '3030', "Whilst falling back to redux options a global variable with name $name is not properly configured." );
            }

            /**
             * Same as get_global_var but will try and interpret the value of the
             * global variable as if it is a boolean. 
             * 
             * @since 4.6
             * 
             * @param   string  $name   Name of the global variable to get
             * @return  boolean         True in case value found equals 1, "1", "true" or true, otherwise false.
             */
            public static function get_global_boolean_var( $name ) {
                $var = self::get_global_var( $name );
                return (
                    $var === true 
                    || $var === "1" 
                    || $var === 1 
                    || ( is_string( $var ) && strtolower( $var ) == 'true' ) ) ? true : false;
            }

            /**
             * Shows admin notices when the plugin is not configured correctly
             * 
             * @since 2.3
             * 
             * @return void
             */
            public static function show_admin_notices( ) {

                if(!is_admin()) {
        
                    return;
                }
        
                if( false === self::is_wpo365_configured( false ) ) {
                        echo '<div class="notice notice-error"><p>' . __( 'Please visit https://www.wpo365.com/how-to-install-wordpress-office-365-login-plugin/ for a quick reference on how to properly configure the WPO365-login plugin using the WPO365 menu to your left.' ) . '</p></div>';
                        echo '<div class="notice notice-warning is-dismissible"><p>' . __( 'The Wordpress + Office 365 login plugin protects most of Wordpress but in case of a public facing intranet it is strongly advised to block anonymous access to the Wordpress Upload directory' ) . '</p></div>';
                }

                if( isset( $_GET[ 'page' ] ) && $_GET[ 'page' ] == 'wpo365-options' ) {
                    ?>

                    <div class="notice notice-info is-dismissible" style="margin-top: 25px;">
                        <article style="display: flex; flex-wrap: wrap;">
                            <div style="flex-grow: 0.1; flex-shrink: 0.9;">
                                <img width="256" height="256" src="https://www.wpo365.com/wp-content/uploads/2018/04/premium-icon-256x256.png">
                            </div>
                            <div style="flex-grow: 0.9; flex-shrink: 0.1; padding-left: 10px;">
                                <div>
                                    <h2>WordPress + Office 365 login premium</h2>
                                </div>
                                <div>
                                    <p><strong><a href="https://www.wpo365.com/downloads/wordpress-office-365-login-premium/" target="_blank">Upgrade</a></strong> today and unlock the following premium features</p>
                                    <ul style="list-style: inherit; margin-left: 20px;">
                                        <li>Creating and adding unlimited Office 365 users</li>
                                        <li>The ability to <strong><a href="https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/" target="_blank">quickly rollout new users to WordPress</a></strong> from Active Directory</li>
                                        <li><strong><a href="https://www.wpo365.com/synchronize-users-between-office-365-and-wordpress/" target="_blank">Disable user access</a></strong> to WordPress for users that are disabled in your tenant / domain</li>
                                        <li>Enriches a user’s WordPress profile with <strong><a href="https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization/" target="_blank">O365 user profile info</a></strong> e.g. job title, phone and office location</li>
                                        <li>Enhanced security e.g. <strong><a href="https://codex.wordpress.org/Brute_Force_Attacks" target="_blank">Brute Force Attacks</a></strong> prevention</li>
                                        <li>Replaces a user’s default <strong><a href="https://www.wpo365.com/configuring-office-365-profile-and-avatar-synchronization/" target="_blank">WordPress avatar</a></strong> with the Office 365 (O365) profile picture and caches it</li>
                                        <li>Imposes Role Access Control for WordPress based on Office 365 or Azure AD <strong>Security groups</strong></li>
                                        <li>Automated WordPress Role Assignment using a <strong>configurable mapping</strong> between Office 365 or Azure AD Security groups and WordPress roles</li>
                                        <li>Plain wp-config.php configuration (improves the overall <strong>performance</strong> of your website)</li>
                                        <li>One <strong>support</strong> item included</li>
                                    </ul>
                                </div>
                            </div>
                        </article>
                    </div>

                    <?php
                    echo '<div class="notice notice-warning is-dismissible"><p>' . __( 'The Wordpress + Office 365 login plugin protects most of Wordpress but in case of a public facing intranet it is strongly advised to block anonymous access to the Wordpress Upload directory' ) . '</p></div>';
                }    
            }

            /**
             * Adds no-cache headers to the headers sent when the desired authentication scenario is "Intranet"
             * 
             * @since 2.4
             * 
             * @return void
             */
            public static function add_no_cache_headers() {

                if( headers_sent() ) {

                    Logger::write_log( 'ERROR', 'Could not write additional headers to prevent caching because headers already sent.' );
                    return;
                }

                if( defined( 'WPO_NOCACHE' ) && true === WPO_NOCACHE ) {

                    // set headers to NOT cache a page
                    nocache_headers();
                    return;
                }
            }
        }
    }

?>