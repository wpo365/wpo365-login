<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    class Logger {
        /**
         * Writes a message to the Wordpress debug.log file
         *
         * @since   1.0
         * @param   string  level => The level to log e.g. DEBUG or ERROR
         * @param   string  log => Message to write to the log
         */
        public static function write_log( $level, $log ) {

            // Don't log debug level if not explicitely requested
            if( $level == 'DEBUG' 
               && ( !isset( $GLOBALS['wpo365_options']['debug_mode'] ) 
               || $GLOBALS['wpo365_options']['debug_mode'] != 1 ) ) {

                return;

            }
            
            if ( is_array( $log ) || is_object( $log ) ) {

                // Print array data
                error_log( $level . ' ( ' . phpversion() .' ): '. print_r( $log, true ) );

            } else {

                // Or just the message passed in as a string
                error_log( $level . ' ( ' . phpversion() .' ): ' . $log );
                
            }
        }
    }

?>