<?php

    namespace Wpo\User;
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();
    
    use \Wpo\Util\Logger;
    use \Wpo\Util\Helpers;
    use \Wpo\Aad\Auth;
    use \Wpo\User\User;
    use \Wpo\Util\Error_Handler;

    if( !class_exists( '\Wpo\User\User_Manager' ) ) {
    
        class User_Manager {

            const USER_NOT_LOGGED_IN = 0;
            const IS_NOT_O365_USER = 1;
            const IS_O365_USER = 2;

            /**
             * Checks whether a user identified by an id_token received from
             * Microsoft matches with an existing Wordpress user and if not creates it
             *
             * @since   1.0
             * @param   string  id_token => received from Microsoft's openidconnect endpoint
             * @return  mixed(WP_User|NULL) WP_User when user could be ensured or else NULL
             */
            public static function ensure_user( $decoded_id_token ) {
                if( empty( $decoded_id_token ) ) {
                    Logger::write_log( 'ERROR', 'Cannot ensure user because id_token empty' );
                    return NULL;
                }

                // Translate id_token in a Wpo\User\User object
                $wpo_usr = User::user_from_id_token( $decoded_id_token );

                if( empty( $wpo_usr) ) {
                    Logger::write_log( 'DEBUG', 'Could not retract UPN from id token' );
                    return NULL;                
                }

                // Check whether the user's domain is white listed (if empty this check is skipped)
                $domain_white_list = Helpers::get_global_var( 'WPO_DOMAIN_WHITELIST' );
                $smtp_domain = Helpers::get_smtp_domain_from_email_address( $wpo_usr->email );

                if( !is_wp_error( $domain_white_list ) 
                    && strlen( trim( $domain_white_list ) ) > 0 ) {
                        
                        if( empty( $smtp_domain )
                            || false === strpos( $domain_white_list, $smtp_domain ) ) {
                                Logger::write_log( 'DEBUG', 'Cannot continue since the domain the user is coming from is not whitelisted or the smtp domain could not be determined (' . $wpo_usr->upn . ')' );
                                return NULL;
                        }
                }
                
                // Try find an existing user by email
                $wp_usr = empty( $wpo_usr->email ) ? NULL : get_user_by( 'email', $wpo_usr->email );

                // Or else try find by upn
                if( empty( $wp_usr ) )
                    $wp_usr = empty( $wpo_usr->upn ) ? NULL : get_user_by( 'login', $wpo_usr->upn );

                // Get target site info
                $site_info = Helpers::target_site_info( $_POST[ 'state' ] );

                if( $site_info == null ) {
                    Logger::write_log( 'DEBUG', 'Could not retrieve necessary site info needed to continue' );
                    return NULL;
                }

                $create_users_and_add = Helpers::get_global_boolean_var( 'WPO_CREATE_ADD_USERS' );
                // Create a new WP user if not found but only if desired
                if( empty( $wp_usr ) ) {

                    if( true === $create_users_and_add ) {

                        if( User_Manager::user_count( $smtp_domain ) >= 3 ) {
                            Logger::write_log( 'ERROR', 'Cannot create more than three users with the Personal Blog (free) version of the plugin' );
                            Auth::goodbye( Error_Handler::PERSONAL_BLOG_LIMIT );
                            // --> exit()
                        }

                        // Add the user with the default role to the current site
                        // In case of Wordpress Multisite the user is added to the main site 
                        // but will not be added to the targeted site
                        $wp_usr = User_Manager::add_user( $wpo_usr );

                        if( empty( $wp_usr ) ) {
                            Logger::write_log( 'DEBUG', 'Could not create user with user principal name ' . $wpo_usr->upn );
                            return NULL;
                        }
                    }
                    else {
                        Logger::write_log( 'DEBUG', 'User not found and settings prevented creating a new user on-demand' );
                        return NULL; // User not found and new users shall not be created
                    }
                } // else wp user already created so continue

                // In case of multi site add user to target site but only if desired
                if( $site_info[ 'is_multi' ] ) {
                    $mu_new_usr_default_role = Helpers::get_global_var( 'WPO_DEFAULT_ROLE_SUB_SITE' );
                    
                    if( !is_wp_error( $mu_new_usr_default_role ) 
                        && !is_user_member_of_blog( 
                            $wp_usr->ID, 
                            $site_info[ 'blog_id' ] ) 
                        && $create_users_and_add ) {
                            add_user_to_blog( 
                                $site_info[ 'blog_id' ], 
                                $wp_usr->ID, 
                                $mu_new_usr_default_role );
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
                $session_duration = Helpers::get_global_var( 'WPO_SESSION_DURATION' );
                $session_duration = is_wp_error( $session_duration ) ? 3480 : $session_duration;
                $expiry = time() + intval( $session_duration );

                // Obfuscated user's wp id
                $obfuscated_user_id = $expiry + $wp_usr->ID;
                update_user_meta( 
                    get_current_user_id(),
                    Auth::USR_META_WPO365_AUTH,
                    "$expiry,$obfuscated_user_id" );

                return $wp_usr;
            }

            /**
             * Creates a new Wordpress user
             *
             * @since   1.0
             * @param   User    usr => User instance holding all necessary data
             * @return  mixed(WP_User|NULL)
             */

            public static function add_user( $usr ) {

                $role = Helpers::get_global_var( 'WPO_DEFAULT_ROLE_MAIN_SITE' );

                if( is_wp_error( $role ) ) {
                    Logger::write_log( 
                        'ERROR', 
                        'No default role defined for user' );
                    return NULL;
                }

                $userdata = array( 
                    'user_login'    => $usr->upn,
                    'user_pass'     => uniqid(),
                    'displayname'   => $usr->full_name,
                    'user_email'    => $usr->email,
                    'first_name'    => $usr->first_name,
                    'last_name'     => $usr->last_name,
                    'last_name'     => $usr->last_name,
                    'role'          => strtolower( trim( $role ) ),
                );

                // Insert in Wordpress DB
                $wp_usr_id = wp_insert_user( $userdata );

                if( is_wp_error( $wp_usr_id ) ) {
                    Logger::write_log( 
                        'ERROR', 
                        'Could not create wp user with user principal name ' . $usr->upn );
                    Logger::write_log( 
                        'ERROR', 
                        $wp_usr_id );
                    return NULL;
                }
                
                // Add an extra meta information that this user is in fact a user created by WPO365
                add_user_meta( $wp_usr_id, 'auth_source', 'AAD', true );
                $wp_usr = get_user_by( 'id', $wp_usr_id );
                return $wp_usr;
            }

            /**
             * Checks whether current user is O365 user
             *
             * @since   1.0
             * @return  int One of the following User_Manager class constants 
             *              USER_NOT_LOGGED_IN, IS_O365_USER or IS_NOT_O365_USER
             */
            public static function user_is_o365_user( $user_id ) {
                $wp_usr = get_user_by( 'ID', intval( $user_id ) );

                if( $wp_usr === false ) {
                    Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> Not logged on' );
                    return self::USER_NOT_LOGGED_IN;
                }

                $custom_domain = Helpers::get_global_var( 'WPO_CUSTOM_DOMAIN' );
                $default_domain = Helpers::get_global_var( 'WPO_DEFAULT_DOMAIN' );

                if( is_wp_error( $custom_domain )
                    && is_wp_error( $default_domain ) ) {

                        // Try and determine it the "old" way
                        $wp_usr = wp_get_current_user();
                        $usr_meta = get_user_meta( $wp_usr->ID );
                        
                        if( !isset( $usr_meta[ 'auth_source' ] ) ) {
                            Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> NO' );
                            return self::IS_NOT_O365_USER;
                        }

                        if( strtolower( $usr_meta[ 'auth_source' ][0] ) == 'aad' ) {
                            Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> YES' );
                            return self::IS_O365_USER;
                        }
                }

                $email_domain = Helpers::get_smtp_domain_from_email_address( $wp_usr->user_login );

                if( Helpers::is_tenant_domain( $email_domain ) ) {
                    Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> YES' );
                    return self::IS_O365_USER;
                }

                Logger::write_log( 'DEBUG', 'Checking whether user is O365 user -> NO' );
                return self::IS_NOT_O365_USER;
            }

            /**
             * Returns true when a user is allowed to change the password
             *
             * @since   1.0
             * @return  void
             * 
             * @return boolean true when a user is allowed to change the password otherwise false
             */
            public static function show_password_fields( $show, $user ) {

                return !User_Manager::block_password_update( $user->ID );
            }

            /**
             * Returns true when a user is allowed to change the password
             * 
             * @since 1.5
             * 
             * @param boolean  $allow whether allowed or not
             * @param int      $user_id id of the user for which the action is triggered
             * 
             * @return boolean true when a user is allowed to change the password otherwise false
             */
            public static function allow_password_reset( $allow, $user_id ) {
                return !User_Manager::block_password_update( $user_id );
            }

            /**
             * Helper method to determin whether a user is allowed to change the password
             * 
             * @since 1.5
             * 
             * @param int   $user_id id of the user for which the action is triggered
             * 
             * @return boolean true when a user is not allowed to change the password otherwise false
             */
            private static function block_password_update( $user_id ) {
                $block_password_change = Helpers::get_global_var( 'WPO_BLOCK_PASSWORD_UPDATE' );

                // Not configured or not blocked
                if( is_wp_error( $block_password_change ) 
                    || $block_password_change === false 
                    || $block_password_change == "0" ) { // user is not logged on

                        Logger::write_log( 'DEBUG', 'Not blocking password update' );
                        return false;
                }

                // Limit the blocking of password update only for O365 users
                return User_Manager::user_is_o365_user( $user_id ) === User_Manager::IS_O365_USER ? true : false;
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
            public static function prevent_email_change( $user_id ) {

                // Don't block as per global settings configuration
                if( false === Helpers::get_global_boolean_var( 'WPO_BLOCK_EMAIL_UPDATE' ) 
                    || User_Manager::user_is_o365_user( $user_id ) !== User_Manager::IS_O365_USER )
                        return;

                $usr_old = get_user_by( 'ID', intval( $user_id ) );

                if( $usr_old === false )
                    return;

                // At this point the user is an O365 user and email change should be blocked as per config
                if( isset( $_POST[ 'email' ] ) && $_POST[ 'email' ] != $usr_old->user_email ) {

                    // Prevent update
                    $_POST[ 'email' ] = $usr_old->user_email;
                    
                    add_action( 'user_profile_update_errors', function( $errors ) {
                        $errors->add( 'email_update_error' ,__( 'Updating your email address is currently not allowed' ) );
                    });
                }
            }

            /**
             * Simple helper to count number of O365 users currently in WordPress.
             * 
             * @since 6.0
             * 
             * @return int Number of O365 users currently in WordPress.
             */
            private static function user_count( $smtp_domain ) {
                $user_query = new \WP_User_Query( 
                    array(
                        'search'            => "*$smtp_domain",
                        'search_columns'    => array( 
                            'user_login' 
                        ),
                    )
                );

                return $user_query->get_total();
            }
        }
    }

?>