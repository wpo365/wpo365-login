<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    use \Wpo\Util\Logger;

    if( !class_exists( '\Wpo\Util\Helpers' ) ) {

        class Helpers {
            
            /**
             * Prevents wordpress from replacing &nbps; and \n with <p> and <br> inside wpo365 shortcodes
             * 
             * @since 2.0
             */
            public static function update_wpautop_formatting() {

                // User expicitely disabled this functionality
                if( isset( $GLOBALS['wpo365_options'] ) 
                    && $GLOBALS['wpo365_options']['replace_wpautop'] != 1 ) {

                    return;

                }
                
                // Remove the default Wordpress filter
                remove_filter( 'the_content', 'wpautop' );

                // Add our custom filter that only applies wpautop outside of our shortcodes
                add_filter( 'the_content', function( $content ) {
                    
                    // Find start of short code
                    $sc_start = strpos( $content, '[wpo365' );
                    
                    // No wpo365 shortcode found
                    if( $sc_start === false ) {

                        return wpautop( $content );

                    }

                    $result = '';
                    $content_after = '';
                    
                    // No loop through content and search for short codes ( there could be more than one )
                    while( $sc_start !== false ) {
                        
                        $sc_stop = strpos( $content, '-sc]' ) + 4;
                    
                        $content_before = wpautop( substr( $content, 0, $sc_start ) );
                        $short_code = substr( $content, $sc_start, $sc_stop - $sc_start );
                        $content = wpautop( substr( $content, $sc_stop ) ); // Content becomes the tail
                        
                        $result = $content_before . $short_code; // Save content before shortcode plus short code
                        $sc_start = strpos( $content, '[wpo365' ); // Check tail for more wpo365 shortcodes

                    }

                    return $result . $content; // Finally add tail and return
                } ); 
            }

            /**
             * Gets the domain (host) part of an email address.
             * 
             * @since 3.1
             * 
             * @param   string  $email_address  email address to analyze
             * @return  (mixed|boolean|string)  returns false if email cannot be validated and otherwise the 
             *                                  email address' host part
             */
            public static function get_smtp_domain_from_email_address( $email_address ) {

                if( filter_var( trim( $email_address ), FILTER_VALIDATE_EMAIL ) !== false ) {

                    return   strtolower( trim( substr( $email_address, strrpos( $email_address, '@' )  + 1 ) ) );

                }

                return false;

            }

            /**
             * Creates a nonce using the nonce_secret
             * 
             * @since 3.10
             * 
             * @return (string|WP_Error) nonce as a string otherwise an WP_Error (most likely when dependency are missing)
             */
            public static function get_nonce() {

                $nonce_salt = constant( 'NONCE_SALT' );
                
                if( empty( $nonce_salt ) ) {

                    Logger::write_log( 'ERROR', 'Global var NONCE_SALT not defined' );
                    return new \WP_Error( '', 'Nonce salt not defined' );

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
             * @since 3.10
             * 
             * @param string $nonce encoded nonce value to validate
             * @return (boolean|WP_Error) true when valide otherwise WP_Error
             */
            public static function validate_nonce( $nonce ) {

                $nonce_salt = constant( 'NONCE_SALT' );

                if( empty( $nonce_salt ) ) {

                    Logger::write_log( 'ERROR', 'Global var NONCE_SALT not defined' );
                    return new \WP_Error( '', 'Nonce salt not defined' );

                }

                $nonce_secret = $nonce_salt;

                if( isset( $GLOBALS['wpo365_options'] ) && isset( $GLOBALS['wpo365_options']['nonce_secret'] ) ) {

                    $nonce_secret = $GLOBALS['wpo365_options']['nonce_secret'];

                }

                $decoded = base64_decode( $nonce );

                if ($decoded === false) {
                
                    Logger::write_log( 'ERROR', 'Your login has been tampered with [decoding failed]' );
                    return new \WP_Error( '', 'Your login has been tampered with [decoding failed]' );

                }

                $message = json_decode( $decoded );

                $nonce_hash = hash_hmac( 'sha256', $nonce_secret, $nonce_salt, false );

                if( $message->nonce != $nonce_hash ) {

                    Logger::write_log( 'ERROR', 'Your login has been tampered with [hash does not match]' );
                    return new \WP_Error( '', 'Your login has been tampered with [hash does not match]' );

                }

                if ( time() > intval( $message->expires ) ) {
                    
                    Logger::write_log( 'ERROR', 'Your login has been tampered with [nonce expired]' );
                    return new \WP_Error( '', 'Your login has been tampered with [nonce expired]' );

                }

                Logger::write_log( 'DEBUG', 'Nonce message: ' . $message->nonce );

                return true;

            }

            /**
             * Takes a one dimensional set of results and transforms this into 
             * a mulit dimensional array of rows with a max size equal to $cols
             *
             * @since 2.0
             * 
             * @param   array   $results    one dimensional array which items will be rowified
             * @param   int     $cols       Number of items per row in the resulting array ( when zero all items are placed in a single row )
             * @return  array   Multi dimensional array containing rows of items where max size of a row equals $cols
             */
            public static function rowify_results( $results, $cols ) {
            
                Logger::write_log( 'DEBUG', 'Nr. of results: ' . sizeof( $results ) );
                
                if( !is_array( $results ) ) {
                    return array();
                }
            
                $rowified = array();
                $row = array();
                
                for( $i = 0; $i < sizeof( $results ); $i++ ) {

                    // In case of 0 cols are results are placed in one single row
                    if( $cols == 0 ) {

                        array_push( $row, $results[$i] );
                        continue;

                    }
            
                    if( sizeof( $row ) == $cols ) {
            
                        array_push( $rowified, $row );
                        $row = array();
            
                        Logger::write_log( 'DEBUG', 'Pushed row in to overall result' );
                    }
            
                    array_push( $row, $results[$i] );
            
                    Logger::write_log( 'DEBUG', 'Pushed item into a row' );
                }
            
                // push the last row
                if( sizeof( $row ) > 0 ) {
                    array_push( $rowified, $row );
                }
            
                return $rowified;
            }

            /**
             * Parses a query string into an associative array
             *
             * @since   2.0
             *
             * @param   string  $str    Query string thus everthing that follows the '?'
             * @return  associative array that may be empty if something went wrong
             */
            public static function parse_query_str( $str ) {

                // Return empty array in case of no query string
                if( empty( $str ) ) {

                    return array();

                }
                
                // Result array
                $arr = array();
            
                // split on outer delimiter
                $pairs = explode( '&', $str );
            
                // loop through each pair
                foreach ( $pairs as $i ) {

                    // split into name and value
                    list( $name,$value ) = explode( '=', $i );
            
                    // if name already exists
                    if( isset( $arr[$name] ) ) {

                        // stick multiple values into an array
                        if( is_array( $arr[$name] ) ) {

                            $arr[$name][] = $value;

                        }
                        else {

                            $arr[$name] = array( $arr[$name], $value );

                        }

                    }
                    // Otherwise, simply stick it in a scalar
                    else {

                        $arr[$name] = $value;

                    }
                }
            
                # return result array
                return $arr;
            }

            /**
             * Removes query string from string ( there may be an incompatibility with URL rewrite )
             *
             * @since 2.0
             *
             * @return  Current URL as string without query string
             */
            public static function reconstruct_url() {
                
                $reconstructed_url = ( isset( $_SERVER['HTTPS'] ) ? 'https' : 'http' ) . '://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]';
                $pos = strpos( $reconstructed_url, '?' );

                // Remove query string if found
                if( $pos !== false ) {
                    $reconstructed_url = substr( $reconstructed_url, 0, $pos );
                }
            
                return $reconstructed_url;
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
             * @since 2.5
             *
             * @param   string  Name of event to track (default is install)
             * @return  Current URL as string without query string
             */
            public static function track( $event = 'install' ) {

                $plugin_version = $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ];
                $event  = $event == NULL ? 'install' : $event;
                $event .= '_login';

                $ga = "https://www.google-analytics.com/collect?v=1&tid=UA-5623266-11&aip=1&cid=bb923bfc-cae8-11e7-abc4-cec278b6b50a&t=event&ec=alm&ea=$event&el=wpo365-login_$plugin_version";

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
             * Removes query string from string ( there may be an incompatibility with URL rewrite )
             *
             * @since 2.5
             *
             * @return  Current URL as string without query string
             */
            public static function check_version() {
                
                // Get plugin version from db
                $plugin_db_version = get_site_option( 'wpo365-login-version' );

                // Add new option if not yet existing
                if( false === $plugin_db_version ) {

                    add_site_option( 'wpo365-login-version', $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] );

                }
                // Compare plugin version with db version and track in case of update
                elseif( $plugin_db_version != $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] ) {

                    Helpers::track( 'update' );
                    update_site_option( 'wpo365-login-version', $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] );

                }

            }

            /**
             * Shows admin notices when the plugin is not configured correctly
             * 
             * @since 5.0
             * 
             * @return void
             */
            public static function show_admin_notices() {

                if( empty( $GLOBALS[ 'wpo365_options' ][ 'tenant_id' ])
                    || empty( $GLOBALS[ 'wpo365_options' ][ 'application_id' ])
                    || empty( $GLOBALS[ 'wpo365_options' ][ 'redirect_url' ]) ) {

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
             * Disables older wpo365-spo because of incompatibilities
             * 
             * @since 5.0
             * 
             * @param $path
             */
            public static function disable_spo_plugin() {

                $plugins_dir = dirname( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] );
                $spo_plugins_file = $plugins_dir . '/wpo365-spo/wpo365-spo.php';

                if( true === self::old_spo_plugin_exists( $spo_plugins_file ) ) {

                    include_once( ABSPATH . 'wp-admin/includes/plugin.php' );
                    deactivate_plugins( $spo_plugins_file );

                    add_action( 'admin_notices', function() {
                        
                        echo '<div class="notice notice-error"><p>' . __( 'The WordPress + Office 365 login plugin has automatically de-activated an older version of our WordPress + Office 365 SharePoint plugin. Please upgrade to the latest version of this plugin <a href="https://wordpress.org/plugins/wpo365-spo/">or acquire the premium version</a> to avoid compatibility issues. This message will automatically disappear as soon as you have installed version 1.0 or higher of our SharePoint (free or premium) plugin.' ) . '</p></div>';
                    }, 10, 0 );
                }                
            }

            private static function old_spo_plugin_exists( $spo_plugins_file ) {

                try {

                    if( file_exists( $spo_plugins_file ) ) {

                        $version = get_site_option( 'wpo365-spo-version', null );

                        if( !empty( $version ) && floatval( $version ) < 1 ) {

                            return true;
                        }
                    }
                }
                catch(Exception $e) {

                    Logger::write_log( 'ERROR', 'Error occurred whilst trying to deactivate older version of wpo365-spo plugin' );
                } 
                return false;
            }
        }
    }
