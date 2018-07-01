<?php

    require_once( dirname( dirname( __FILE__ ) ) . '\wpo365-login.php' );

    class Foo_Test extends \WP_UnitTestCase {

        public function test_foo_is_foo() {
            $this->assertTrue( 'foo' === 'ftoo' );
        }
    }

?>