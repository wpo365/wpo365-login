<?php

    namespace Wpo\User;
    
    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    // Require dependencies
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/Logger/Logger.php");
    require_once($GLOBALS["WPO365_PLUGIN_DIR"] . "/Wpo/User/User.php");

    use \Wpo\Logger\Logger;
    
    class User_Manager {

        /**
         * Checks whether a user identified by an id_token received from
         * Microsoft matches with an existing Wordpress user and if not creates it
         *
         * @since   1.0
         * @param   string  id_token => received from Microsoft's openidconnect endpoint
         * @return  bool    true when user could be ensured or else false
         */
         public static function ensure_user($id_token) {

            // Validate the incoming argument
            if(empty($id_token)) {

                Logger::write_log("ERROR", "Cannot ensure user because id_token empty");
                return false;
            }

            // Translate id_token in a Wpo\User\User object
            $usr = User::user_from_id_token($id_token);

            // Try find an existing user by email
            $wp_usr = get_user_by("email", $usr->email);

            // Or create one if not found
            if($wp_usr === false) {
                User_Manager::add_user($usr);                
            }

            // Save the user's ID in a session var
            Logger::write_log("DEBUG", "found user with ID " . $wp_usr->ID);
            $_SESSION["WPO365_WP_USR_ID"] = $wp_usr->ID;
            $_SESSION["WPO365_EXPIRY"] = time() + intval($GLOBALS["wpo365_options"]["session_duration"]);

            // Finally log the user on
            wp_set_auth_cookie($wp_usr->ID, true);
            return true;
        }

        /**
         * Creates a new Wordpress user
         *
         * @since   1.0
         * @param   User    usr => User instance holding all necessary data
         * @return  WPUser
         */
        public static function add_user($usr) {
            $userdata = array(
                "user_login" => $usr->upn,
                "user_pass" => uniqid(),
                "user_nicename" => $usr->full_name,
                "displayname" => $usr->full_name,
                "user_email" => $usr->email,
                "first_name" => $usr->first_name,
                "last_name" => $usr->last_name,
                "last_name" => $usr->last_name,
                "role" => "subscriber"
            );

            // Insert in Wordpress DB
            $wp_usr = wp_insert_user($userdata);

            // Add an extra meta information that this user is in fact a user created by WPO365
            add_user_meta($wp_usr, "auth_source", "AAD", true);

            return $wp_usr;
        }

        /**
         * Creates a new Wordpress user
         *
         * @since   1.0
         * @return  void
         */
        public static function user_is_o365_user() {
            if(is_user_logged_in()) {
                $wp_usr = wp_get_current_user();
                $usr_meta = get_user_meta($wp_usr->ID);
                if(!isset($usr_meta["auth_source"])) {
                    Logger::write_log("DEBUG", "Checking whether user is O365 user -> NO");
                    return false; // user is not an O365 user
                }
                if(strtolower($usr_meta["auth_source"][0]) == "aad") {
                    Logger::write_log("DEBUG", "Checking whether user is O365 user -> YES");
                    return true; // user is an O365 user
                }
            }
            Logger::write_log("DEBUG", "Checking whether user is O365 user -> Not logged on");
            return NULL; // user is not logged on TODO implement customer error handling
        }

        /**
         * Returns false for users that are Office 365 users
         *
         * @since   1.0
         * @return  void
         */
        public static function show_password_change_and_reset() {

            $is_o365_usr = User_Manager::user_is_o365_user();
            return $is_o365_usr === true || $is_o365_usr === NULL ? false : true; // Allow password change for native WP users
        }

        /**
         * Prevents users who cannot create new users to change their email address
         *
         * @since   1.0
         * @param   array   errors => Existing errors (from Wordpress)
         * @param   bool    update => true when updating an existing user otherwise false
         * @param   WPUser  usr_new => Updated user
         * @return  void
         */
        public static function prevent_email_change($errors, $update, $usr_new) {   

            $usr_old = wp_get_current_user();
            $usr_meta = get_user_meta($usr_old->ID);

            if(isset($_POST["email"])
                && isset($usr_meta["auth_source"]) 
                && strtolower($usr_meta["auth_source"][0]) == "aad"
                && $_POST["email"] != $usr_old->user_email) {

                // Prevent update
                $errors->add("email_update_error" ,__("Updating your email address is currently not allowed"));
                return;
            }
        }

    }

?>