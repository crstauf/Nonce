# _Nonce_

A helper for creating WordPress nonces.

## Documentation

### Static and Magic Functions

#### `Nonce::register()`

Registering a _Nonce_ stores the object, making it accessible later using `Nonce::get()` via a specified key.

```php
Nonce::register( 'example', 'The Nonce example action' );
```

#### `Nonce::get()`

Gets registered _Nonce_ at the specified key.

```php
$nonce = Nonce::get( 'example' );
```

#### `new Nonce()`

_Nonces_ do not have to be registered: they can be created on the fly, and stored elsewhere.

|Parameter|Description|
|:---|:---|
|`$format`|Format of the nonce's action, for use within `vsprintf()`. Default: `-1`.|
|`$debug_args`|Array of values for the `vsprintf()` when `__debugInfo()` function is called.|

```php
$nonce = new Nonce( 'update Post %s (%d)', array( 'post_name', rand( 1, 100 ) ) );
```

#### `echo Nonce`

Printing a _Nonce_ object will print the nonce, without replacing the conversion specifications with values.

```php
$nonce = new Nonce( 'update Post %s (%d)' );
echo $nonce;
// equivalent to wp_create_nonce( 'update Post %s (%d)' )
```

#### `Nonce()`

You can invoke the _Nonce_ object to get the nonce's token, using the passed arguments.

```php
$nonce = new Nonce( 'update Post %s (%d)' );
$token = $nonce( 'post_name', 392 );
// $token === $nonce->token( 'post_name', 392 )
// $token === wp_create_nonce( 'update Post post_name (392)' )
```

### Output Functions

#### `Nonce->action()`

Gets the action of the nonce.

```php
$nonce = new Nonce( 'update Post %s (%d)' );
echo $nonce->action( 'post_name', 392 );
// "update Post post_name (392)"
```

#### `Nonce->token()`

Gets the nonce (token).

```php
$nonce = new Nonce( 'update Post %s (%d)' );
$token = $nonce->token( 'post_name', 392 );
// $token === wp_create_nonce( 'update Post post_name (392)' )
```

#### `Nonce->field()`

Get the HTML for the nonce form fields.

|Parameter|Description|
|:---|:---|
|`$args`|Array of values for the conversion specifications in the `format` property, to generate the action and token.|
|`$name`|Form field's name. Default: `_wpnonce`.|
|`$referrer`|Bool to include the referrer field. Default: `true`.|

```php
$nonce = new Nonce( 'update Post %s (%d)' );
echo $nonce->field( array( 'post_name', 392 ), '_wpnonce', false );
// <input type="hidden" id="_wpnonce" name="_wpnonce" value="{NONCE}}" />
```

#### `Nonce->url()`

Add the nonce onto a URL.

|Parameter|Description|
|:---|:---|
|`$args`|Array of values for the conversion specifications in the `format` property, to generate the action and token.|
|`$name`|Query argument name. Default: `_wpnonce`.|
|`$url`|URL to add the nonce onto. Default: `false` (uses the current URL).|

```php
$nonce = new Nonce( 'update Post %s (%d)' );
echo $nonce->url( array( 'post_name', 392 ), '_wpnonce', 'https://google.com' );
// https://google.com?_wpnonce={NONCE}
```

### Verification Functions

#### `Nonce->verify()`

Verify the provided value matches the nonce's action.

|Parameter|Description|
|:---|:---|
|`$value`|Value to compare to the token.|
|`$args`|Array of values for the conversion specifications in the `format` property, to generate the action.|

```php
$nonce = new Nonce( 'update Post %s (%d)' );
$verified = $nonce->verify( $_POST['_wpnonce'], 'post_name', 392 );
// $verified === true if $_POST['_wpnonce'] value matches nonce
```

#### `Nonce->verify_ajax()`

Verify nonce in AJAX request.

|Parameter|Description|
|:---|:---|
|`$args`|Array of values for the conversion specifications in the `format` property, to generate the action.|
|`$name`|Name of key to check for nonce in `$_REQUEST`. Default: `false`.|
|`$die`|Bool to terminate script execution if nonce is invalid.|

```php
$nonce = new Nonce( 'update Post %s (%d)' );
$verified = $nonce->verify_ajax( array( 'post_name', 392 ), false, false );
// $verified === true if value of $_REQUEST['_ajax_nonce'] or $_REQUEST['_wpnonce'] matches nonce
```

#### `Nonce->verify_admin()`

Verify nonce is valid within admin context.

|Parameter|Description|
|:---|:---|
|`$args`|Array of values for the conversion specifications in the `format` property, to generate the action.|
|`$name`|Name of key to check for nonce in `$_REQUEST`. Default: `_wpnonce`.|

```php
$nonce = new Nonce( 'update Post %s (%d)' );
$verified = $nonce->verif_admin( array( 'post_name', 392 ) );
// $verified === true if value of $_REQUEST['_wpnonce'] matches nonce, and referrer is the admin
```

### Debug Functions

#### `Nonce::__debugInfo()`

Returns an array of properties and functions using debug data provided in the `debug_args` property.

```php
$nonce = new Nonce( 'update Post %s (%d)' );
print_r( $nonce );
```

#### `Nonce->extra_debug_info()`

Returns an array of values that `wp_create_nonce()` uses to generate the nonce.

```php
$nonce = new Nonce( 'update Post %s (%d)' );
print_r( $nonce->extra_debug_info() );
```