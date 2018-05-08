<?php

    namespace Wpo\User;

    // prevent public access to this script
    defined( 'ABSPATH' ) or die();
    
    class User {

        /**
		 * Email address of user
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $email = null;

        /**
		 * Unique user's principal name
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $upn = null;

        /**
		 * Name of user
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $name = null;

        /**
		 * User's first name
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $first_name = null;

        /**
		 * User's last name incl. middle name etc.
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $last_name = null;

        /**
		 * User's full ( or display ) name
		 *
		 * @since 1.0.0
		 *
		 * @var string
		 */
        public $full_name = null;

        /**
		 * Parse id_token received from Azure Active Directory and return User object
		 *
		 * @since 1.0
		 *
		 * @param string 	$id_token  token received from Azure Active Directory
		 * @return User  	A new User Object created from the id_token
		 */
        public static function user_from_id_token( $id_token ) {

			// Try and detect an MSA account that has no upn but instead an email property
			$email = isset( $id_token->email ) ? $id_token->email : 
				( isset( $id_token->upn ) ? $id_token->upn : '' );
			
			// Stop processing if email could not be found
			if( strlen( $email ) == 0 ) {

				return NULL;

			}

			// Update upn for MSA with email
			$upn = isset( $id_token->upn ) ? $id_token->upn : $email;

			$unique_name = isset( $id_token->unique_name ) ? $id_token->unique_name : $upn;

			$usr = new User();
			
            $usr->first_name = isset( $id_token->given_name ) ?  $id_token->given_name : '';
            $usr->last_name = isset( $id_token->family_name ) ? $id_token->family_name : '';
            $usr->full_name = isset( $id_token->name ) ? $id_token->name : '';
            $usr->email = $email;
            $usr->upn = $upn;
            $usr->name = $unique_name;
			return $usr;
			
        }

    }

?>