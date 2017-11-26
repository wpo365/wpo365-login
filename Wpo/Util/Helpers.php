<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Logger.php' );

    use \Wpo\Util\Logger;

    class Helpers {
        
        /**
         * Simple cookie setter helper method that automatically adds host and path
         *
         * @since   1.4
         * @return  void
         */
        public static function set_cookie( $name, $value, $expiry ) {
            
            setcookie( $name, $value, $expiry, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN );
            setcookie( $name, $value, $expiry, ADMIN_COOKIE_PATH, COOKIE_DOMAIN );
            setcookie( $name, $value, $expiry, COOKIEPATH, COOKIE_DOMAIN );
            if ( COOKIEPATH != SITECOOKIEPATH ) {
                setcookie( $name, $value, $expiry, SITECOOKIEPATH, COOKIE_DOMAIN );
            }

            // add to current request   
            /* if( !isset( $_COOKIE[ $name ] ) ) {

                $_COOKIE[ $name ] = $value;

            } */

            Logger::write_log( 'DEBUG', "Setting cookie $name with value $value" );

        }

        /**
         * Simple cookie getter helper
         *
         * @since   1.4
         * @return  mixed   cookie or if not found false
         */
        public static function get_cookie( $name ) {

            if( !isset( $_COOKIE[$name] ) ) {
                return false;
            }

            return $_COOKIE[$name];

        }

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
            if( $plugin_db_version != $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] ) {

                Helpers::track( 'update' );
                update_site_option( 'wpo365-login-version', $GLOBALS[ 'PLUGIN_VERSION_wpo365_login' ] );

            }

        }

    }

?>