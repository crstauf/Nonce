<?php
/**
 * Plugin name: Nonce
 * Description: A drop-in helper for WordPress nonces.
 * Author: Caleb Stauffer
 * Author URI: develop.calebstauffer.com
 * Version: 1.0
 */

if ( ! defined( 'WPINC' ) || ! function_exists( 'add_filter' ) ) {
	header( 'Status: 403 Forbidden' );
	header( 'HTTP/1.1 403 Forbidden' );
	exit();
}

/**
 * Class.
 */
class Nonce {

	/**
	 * @var self[] Registered Nonces.
	 */
	protected static $nonces = array();

	/**
	 * @var string Format for the nonce's action.
	 */
	protected $format = '';

	/**
	 * @var mixed[] Arguments for debugging.
	 */
	public $args = array();


	/*
	 ######  ########    ###    ######## ####  ######
	##    ##    ##      ## ##      ##     ##  ##    ##
	##          ##     ##   ##     ##     ##  ##
	 ######     ##    ##     ##    ##     ##  ##
	      ##    ##    #########    ##     ##  ##
	##    ##    ##    ##     ##    ##     ##  ##    ##
	 ######     ##    ##     ##    ##    ####  ######
	*/

	/**
	 * Register a Nonce.
	 *
	 * Creates a Nonce, and adds it to cache.
	 *
	 * @param string $key
	 * @param string|int $format
	 * @param mixed[] $args
	 *
	 * @return void
	 */
	public static function register( string $key, $format = -1, array $args = array() ) : void {
		if ( isset( static::$nonces[ $key ] ) ) {
			trigger_error( sprintf( 'Nonce with key <code>%s</code> is already registered.', $key ) );
			return;
		}

		static::$nonces[ $key ] = new static( $format, $args );
	}

	/**
	 * Get a registered Nonce.
	 *
	 * @param string $key
	 * @return self
	 */
	public static function get( string $key ) : static {
		if ( ! isset( static::$nonces[ $key ] ) ) {
			trigger_error( sprintf( 'Nonce with key <code>%s</code> is not registered.', esc_html( $key ) ) );
			return new static;
		}

		return static::$nonces[ $key ];
	}


	/*
	##     ##    ###     ######   ####  ######
	###   ###   ## ##   ##    ##   ##  ##    ##
	#### ####  ##   ##  ##         ##  ##
	## ### ## ##     ## ##   ####  ##  ##
	##     ## ######### ##    ##   ##  ##
	##     ## ##     ## ##    ##   ##  ##    ##
	##     ## ##     ##  ######   ####  ######
	*/

	/**
	 * Construct.
	 *
	 * @var string|int $format Format of the nonce action, for use with sprintf().
	 * @var mixed[] $args Arguments to use for debugging.
	 */
	public function __construct( $format = -1, array $args = array() ) {
		$this->format = $format;

		if ( empty( $args ) ) {
			return;
		}

		$this->args = $args;
	}

	/**
	 * To string.
	 *
	 * @uses $this->token()
	 * @return string
	 */
	public function __toString() : string {
		return $this->token();
	}

	/**
	 * Getter.
	 *
	 * @param string $key
	 * @return mixed
	 */
	public function __get( string $key ) {
		return $this->$key;
	}

	/**
	 * Invoked.
	 *
	 * @param mixed[] $args
	 * @uses $this->token()
	 * @return string
	 */
	public function __invoke( ...$args ) : string {
		return $this->token( ...$args );
	}


	/*
	########  ######## ########  ##     ##  ######
	##     ## ##       ##     ## ##     ## ##    ##
	##     ## ##       ##     ## ##     ## ##
	##     ## ######   ########  ##     ## ##   ####
	##     ## ##       ##     ## ##     ## ##    ##
	##     ## ##       ##     ## ##     ## ##    ##
	########  ######## ########   #######   ######
	*/

	/**
	 * Debug info.
	 *
	 * Manually determine value of verify_admin(), because
	 * check_admin_referer() calls wp_nonce_ays() if nonce
	 * is invalid.
	 *
	 * @see check_admin_referer()
	 *
	 * @uses admin_url()
	 * @uses wp_get_referer()
	 * @uses $this->action()
	 * @uses wp_verify_nonce()
	 * @uses $this->token()
	 * @uses $this->field()
	 * @uses $this->url()
	 * @uses $this->verify()
	 * @uses $this->verify_ajax()
	 *
	 * @return mixed[]
	 */
	public function __debugInfo() : array {
		$adminurl     = strtolower( admin_url() );
		$referer      = strtolower( wp_get_referer() );
		$verify_admin = isset( $_REQUEST[ $query_arg ] )
			? wp_verify_nonce( $_REQUEST[ $query_arg ], $this->action( ...$this->args ) )
			: false;

		return array(

			# Properties.
			'args'               => $this->args,
			'format'             => $this->format,

			# Output functions.
			'__toString()'       => $this->token(  ...$this->args ),
			'action( ...$args )' => $this->action( ...$this->args ),
			'token(  ...$args )' => $this->token(  ...$this->args ),
			'field(     $args )' => $this->field(     $this->args ),
			'url(       $args )' => $this->url(       $this->args ),

			# Verification functions.
			'verify()'           => $this->verify( $this->token( ...$this->args ), ...$this->args ),
			'verify_ajax()'      => $this->verify_ajax( $this->args, '_wpnonce', false ),
			'verify_admin()'     => $verify_admin,

		);
	}

	/**
	 * Extra debug info.
	 *
	 * @see wp_create_nonce()
	 * @see wp_nonce_tick()
	 *
	 * @uses wp_get_current_user()
	 * @uses $this->action()
	 * @uses wp_get_session_token()
	 * @uses wp_nonce_tick()
	 * @uses wp_hash()
	 *
	 * @return mixed[]
	 */
	public function extra_debug_info() : array {
		$uid    = ( int ) wp_get_current_user()->ID;
		$action = $this->action( ...$this->args );

		if ( empty( $uid ) ) {
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		$token = wp_get_session_token();
		$tick  = wp_nonce_tick();
		$hash  = wp_hash( $tick . '|' . $action . '|' . $uid . '|' . $token, 'nonce' );

		return array(
			'uid'                    => $uid,
			'wp_get_session_token()' => $token,
			'wp_nonce_tick()'        => $tick,
			'nonce_life'             => apply_filters( 'nonce_life', DAY_IN_SECONDS ),
			'wp_hash()'              => $hash,
		);
	}


	/*
	 #######  ##     ## ######## ########  ##     ## ########
	##     ## ##     ##    ##    ##     ## ##     ##    ##
	##     ## ##     ##    ##    ##     ## ##     ##    ##
	##     ## ##     ##    ##    ########  ##     ##    ##
	##     ## ##     ##    ##    ##        ##     ##    ##
	##     ## ##     ##    ##    ##        ##     ##    ##
	 #######   #######     ##    ##         #######     ##
	*/

	/**
	 * Nonce action.
	 *
	 * @param mixed[] $args
	 * @return string
	 */
	public function action( ...$args ) : string {
		if ( empty( $args ) ) {
			return $this->format;
		}

		return vsprintf( $this->format, $args );
	}

	/**
	 * Nonce token.
	 *
	 * @param mixed[] $args
	 * @uses $this->action()
	 * @uses wp_create_nonce()
	 * @return string
	 */
	public function token( ...$args ) : string {
		return wp_create_nonce( $this->action( ...$args ) );
	}

	/**
	 * Nonce field.
	 *
	 * @param mixed[] $args
	 * @param string $name
	 * @param bool $referrer
	 *
	 * @uses $this->action()
	 * @uses wp_nonce_field()
	 *
	 * @return string
	 */
	public function field( array $args = array(), string $name = '_wpnonce', bool $referrer = true ) : string {
		return wp_nonce_field( $this->action( ...$args ), $name, $referrer, false );
	}

	/**
	 * Add nonce to URL.
	 *
	 * @param mixed[] $args
	 * @param string $name
	 * @param false|string $url
	 *
	 * @uses $this->action()
	 * @uses add_query_arg()
	 *
	 * @return string
	 */
	public function url( array $args = array(), string $name = '_wpnonce', $url = false ) : string {
		return add_query_arg( $name, $this->token( ...$args ), $url );
	}


	/*
	##     ## ######## ########  #### ######## ##    ##
	##     ## ##       ##     ##  ##  ##        ##  ##
	##     ## ##       ##     ##  ##  ##         ####
	##     ## ######   ########   ##  ######      ##
	 ##   ##  ##       ##   ##    ##  ##          ##
	  ## ##   ##       ##    ##   ##  ##          ##
	   ###    ######## ##     ## #### ##          ##
	*/

	/**
	 * Verify.
	 *
	 * @param string $value
	 * @param mixed[] $args
	 *
	 * @uses $this->action()
	 * @uses wp_verify_nonce()
	 *
	 * @return int
	 */
	public function is_valid( string $value, ...$args ) : int {
		return ( int ) wp_verify_nonce( $value, $this->action( ...$args ) );
	}

	/**
	 * Verify AJAX referer.
	 *
	 * @param mixed[] $args
	 * @param false|string $name
	 * @param bool $die
	 *
	 * @uses $this->action()
	 * @uses check_ajax_referer()
	 *
	 * @return int
	 */
	public function is_valid_for_ajax( array $args = array(), $name = false, bool $die = true ) : int {
		return ( int ) check_ajax_referer( $this->action( ...$args ), $name, $die );
	}

	/**
	 * Verify admin referer.
	 *
	 * @param mixed[] $args
	 * @param string $name
	 *
	 * @uses $this->action()
	 * @uses check_admin_referer()
	 *
	 * @return int
	 */
	public function is_valid_for_admin( array $args = array(), string $name = '_wpnonce' ) : int {
		return ( int ) check_admin_referer( $this->action( ...$args ), $name );
	}

}

add_action( 'init', function() {
	$id    = 'caleb';
	$rand  = 15;
	$nonce = new Nonce( 'qwerty %s %d', array( $id, $rand ) );

	echo $nonce( $id, $rand );
	var_dump( $nonce );

	$action = $nonce->action( $id, $rand );
	$token  = $nonce->token(  $id, $rand );
	$verify = $nonce->is_valid( $token, $id, $rand );

	echo $action . "\n" . $token . "\n" . ( $verify ? 'verified' : 'unverified' );
	exit;
} );