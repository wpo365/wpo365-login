<?php

    namespace Wpo\User;
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    // Require dependencies
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Logger.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Util/Helpers.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/Aad/Auth.php' );
    require_once( $GLOBALS[ 'WPO365_PLUGIN_DIR' ] . '/Wpo/User/User.php' );

    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Aad\Auth;
    
    class User_Manager {

        /**
         * Checks whether a user identified by an id_token received from
         * Microsoft matches with an existing Wordpress user and if not creates it
         *
         * @since   1.0
         * @param   string  id_token => received from Microsoft's openidconnect endpoint
         * @return  bool    true when user could be ensured or else false
         */
         public static function ensure_user( $decoded_id_token ) {

            // Validate the incoming argument
            if( empty( $decoded_id_token ) ) {

                Logger::write_log( 'ERROR', 'Cannot ensure user because id_token empty' );
                return false;
            }

            if( isset( $GLOBALS[ 'wpo365_options' ] )
                && isset( $GLOBALS[ 'wpo365_options' ][ 'debug_log_id_token' ] )
                && $GLOBALS[ 'wpo365_options' ][ 'debug_log_id_token' ] == 1 ) {
                
                    Logger::write_log( 'DEBUG', 'ID token as received from Azure AD Open Connect' );
                    Logger::write_log( 'DEBUG', $decoded_id_token );

            }

            // Translate id_token in a Wpo\User\User object
            $usr = User::user_from_id_token( $decoded_id_token );

            if( $usr == NULL ) {

                Logger::write_log( 'DEBUG', 'Could not retract UPN from id token' );
                return false;
                
            }

            // Check whether the user's domain is white listed (if empty this check is skipped)
            $domain_white_list = !empty( $GLOBALS[ 'wpo365_options' ][ 'domain_whitelist' ] ) ? trim( $GLOBALS[ 'wpo365_options' ][ 'domain_whitelist' ] ) : '';

            if( !empty( $domain_white_list ) ) {

                $smtp_domain = Helpers::get_smtp_domain_from_email_address( $usr->email );

                if( strpos( $domain_white_list, $smtp_domain ) === false ) {

                    Logger::write_log( 'DEBUG', 'Cannot continue since the domain the user is coming from is not whitelisted' );
                    return false;

                }

            }
            
            // Try find an existing user by email
            $wp_usr = get_user_by( 'email', $usr->email );

            // Get target site info
            $site_info = Helpers::target_site_info( $_POST[ 'state' ] );

            if( $site_info == null ) {

                Logger::write_log( 'DEBUG', 'Could not retrieve necessary site info needed to continue' );
                return false;

            }

            $create_users_and_add = isset( $GLOBALS[ 'wpo365_options' ] ) 
                                    && isset( $GLOBALS[ 'wpo365_options' ][ 'create_and_add_users' ] )
                                    && $GLOBALS[ 'wpo365_options' ][ 'create_and_add_users' ] == 1 ? true : false; 

            // Create a new WP user if not found but only if desired
            if( $wp_usr === false ) {

                if( $create_users_and_add ) {

                    // Add the user with the default role to the current site
                    // In case of Wordpress Multisite the user is added to the main site 
                    // but will not be added to the targeted site
                    $wp_usr = User_Manager::add_user( $usr );

                }
                else {

                    Logger::write_log( 'DEBUG', 'User not found and settings prevented creating a new user on-demand' );
                    return false; // User not found and new users shall not be created

                }

            } // else wp user already created so continue
            
            // In case of multi site add user to target site but only if desired
            if( $site_info[ 'is_multi' ] ) {
                
                if( !is_user_member_of_blog( $wp_usr->ID, $site_info[ 'blog_id' ] ) && $create_users_and_add ) {

                    if( isset( $GLOBALS[ 'wpo365_options' ] )
                        && isset( $GLOBALS[ 'wpo365_options' ][ 'new_usr_default_role' ] ) ) {
                            add_user_to_blog( $site_info[ 'blog_id' ], $wp_usr->ID, $GLOBALS[ 'wpo365_options' ][ 'mu_new_usr_default_role' ] );
                    }
                    else {

                        Logger::write_log( 'DEBUG', 'Could not add user to site due to missing configuration (default role for user not found)' );
                        return false;

                    }

                } // else user already added to target site so continue

            } // else not multi site so no need to add user target site explicitely

            // Now log on the user
            wp_set_auth_cookie( $wp_usr->ID, true );  // Both log user on
            wp_set_current_user( $wp_usr->ID );       // And set current user

            // Mark the user as AAD in case he/she isn't ( because manually added but still using AAD to authenticate )
            $usr_meta = get_user_meta( $wp_usr->ID, 'auth_source', true );
            
            if( empty( $usr_meta ) || strtolower( $usr_meta ) != 'aad' ) {

                // Add an extra meta information that this user is in fact a user created by WPO365
                add_user_meta( $wp_usr->ID, 'auth_source', 'AAD', true );

            }

            // Save the user's ID in a session var
            Logger::write_log( 'DEBUG', 'found user with ID ' . $wp_usr->ID );
            
            // Session valid until
            $expiry = time() + intval( $GLOBALS[ 'wpo365_options' ][ 'session_duration' ] );

            // Obfuscated user's wp id
            $obfuscated_user_id = $expiry + $wp_usr->ID;
            
            Auth::set_unique_user_meta( Auth::USR_META_WPO365_AUTH, "$expiry,$obfuscated_user_id" );

            return true;

        }

        /**
         * Creates a new Wordpress user
         *
         * @since   1.0
         * @param   User    usr => User instance holding all necessary data
         * @return  WPUser
         */
        public static function add_user( $usr ) {

            if( !isset( $GLOBALS[ 'wpo365_options' ][ 'new_usr_default_role' ] )
                || empty( $GLOBALS[ 'wpo365_options' ][ 'new_usr_default_role' ] ) ) {
                return false;
            }
            
            // Since 3.0 it's possible to override default user with a setting in wp-config
            $role = defined( 'WPO365_DEFAULT_USER_ROLE' ) ? strtolower( WPO365_DEFAULT_USER_ROLE ) : strtolower( $GLOBALS[ 'wpo365_options' ][ 'new_usr_default_role' ] );
            
            $userdata = array( 
                'user_login'    => $usr->upn,
                'user_pass'     => uniqid(),
                'user_nicename' => $usr->full_name,
                'displayname'   => $usr->full_name,
                'user_email'    => $usr->email,
                'first_name'    => $usr->first_name,
                'last_name'     => $usr->last_name,
                'last_name'     => $usr->last_name,
                'role'          => $role,
            );

            // Insert in Wordpress DB
            $wp_usr_id = wp_insert_user( $userdata );
            
            // Add an extra meta information that this user is in fact a user created by WPO365
            add_user_meta( $wp_usr_id, 'auth_source', 'AAD', true );

            return get_user_by( 'ID', $wp_usr_id );
        }

        /**
         * Checks whether current user is O365 user
         *
         * @since   1.0
         * @return  NULL if not logged in or true if O365 user or false if not
         */
        public static function user_is_o365_user() {

            if( is_user_logged_in() ) {

                $wp_usr = wp_get_current_user();
                $usr_meta = get_user_meta( $wp_usr->ID );
                
                if( !isset( $usr_meta[ 'auth_source' ] ) ) {

                    Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> NO' );
                    return false; // user is not an O365 user

                }

                if( strtolower( $usr_meta[ 'auth_source' ][0] ) == 'aad' ) {

                    Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> YES' );
                    return true; // user is an O365 user

                }
            }

            Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> Not logged on' );
            return NULL; // user is not logged on TODO implement customer error handling
        }

        /**
         * Returns true when changing / resetting password should be allowed for user
         *
         * @since   1.0
         * @return  void
         */
        public static function show_password_change_and_reset() {

            // Don't block configured in global settings
            if( isset( $GLOBALS[ 'wpo365_options' ][ 'block_password_change' ] ) 
                && $GLOBALS[ 'wpo365_options' ][ 'block_password_change' ] == 0 ) {

                return true;

            }

            $is_o365_usr = User_Manager::user_is_o365_user();
            return $is_o365_usr === true || $is_o365_usr === NULL ? false : true; // Allow password change for native WP users
        }

        /**
         * Prevents users who cannot create new users to change their email address
         *
         * @since   1.0
         * @param   array   errors => Existing errors ( from Wordpress )
         * @param   bool    update => true when updating an existing user otherwise false
         * @param   WPUser  usr_new => Updated user
         * @return  void
         */
        public static function prevent_email_change( $errors, $update = NULL, $usr_new = NULL ) {

            // Don't block as per global settings configuration
            if( isset( $GLOBALS[ 'wpo365_options' ][ 'block_email_change' ] ) 
                && $GLOBALS[ 'wpo365_options' ][ 'block_email_change' ] == 0 ) {

                return ;

            }

            $usr_old = wp_get_current_user();
            $usr_meta = get_user_meta( $usr_old->ID );
            
            if( isset( $_POST[ 'email' ] ) 
                && $_POST[ 'email' ] != $usr_old->user_email 
                && isset( $usr_meta[ 'auth_source' ] ) 
                && strtolower( $usr_meta[ 'auth_source' ][0] ) == 'aad' ) {

                    // Prevent update
                    unset( $_POST[ 'email' ] );
                    
                    add_action( 'user_profile_update_errors', function( $errors ) {
                        $errors->add( 'email_update_error' ,__( 'Updating your email address is currently not allowed' ) );
                    });
            }
        }

    }

?>