<?php

    namespace Wpo\Util;

    // Prevent public access to this script
    defined( 'ABSPATH' ) or die();

    if( !class_exists( '\Wpo\Util\Logger' ) ) {

        class Logger {
            /**
             * Writes a message to the Wordpress debug.log file
             *
             * @since   1.0
             * 
             * @param   string  level => The level to log e.g. DEBUG or ERROR
             * @param   string  log => Message to write to the log
             */
            public static function write_log( $level, $log ) {

                if( $level == 'DEBUG' && defined( 'WP_DEBUG' ) && constant( 'WP_DEBUG' ) !== true )
                    return;
                
                if ( is_array( $log ) || is_object( $log ) ) {
                    error_log( $level . ' ( ' . phpversion() .' ): '. print_r( $log, true ) );
                    return;
                }
                
                error_log( $level . ' ( ' . phpversion() .' ): ' . $log );
            }
        }
    }

?>