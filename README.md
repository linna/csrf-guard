<div align="center">
    <a href="#"><img src="logo-linna-128.png" alt="Linna Logo"></a>
</div>

<br/>

<div align="center">
    <a href="#"><img src="logo-csrf.png" alt="Linna framework Logo"></a>
</div>

<br/>

<div align="center">

[![Tests](https://github.com/linna/csrf-guard/workflows/Tests/badge.svg)](https://github.com/linna/csrf-guard/actions)
[![PDS Skeleton](https://img.shields.io/badge/pds-skeleton-blue.svg?style=flat)](https://github.com/php-pds/skeleton)
[![PHP 8.1](https://img.shields.io/badge/PHP-8.1-8892BF.svg)](http://php.net)

</div>

# About
Provide a class for generate and validate tokens utilized against [Cross-site Request Forgery](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)). 
This class uses [random_bytes](http://php.net/manual/en/function.random-bytes.php) function for generate tokens and 
[hash_equals](http://php.net/manual/en/function.hash-equals.php) function for the validation.
> **Note:** Don't consider this class a definitive method to protect your web site/application. If you wish deepen 
how to prevent csrf you can start [here](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet)

# Requirements
This package require 
* php 7.0 until version v1.1.2
* php 7.1 from v1.2.0
* php 7.4 from v1.4.0
* php 8.1 from v2.0.0

# Installation
With composer:
```
composer require linna/csrf-guard
```

# Usage

> **Note:** Session must be started before you create the object's instance, 
if no a `RuntimeException` will be throw

## Create class instance
```php
use Linna\CsrfGuard;

session_start();

//example:
//create new csrf instance with
//64 token stored
//32 byte token length
$csrf = new CsrfGuard(64, 32);
```

## Generate token

Get raw token:
```php
//return token as array that appear like this
//random token name
//32 byte token
//[
//  'name' => string 'csrf_ef2e6d980f7b9430'
//  'value' => string '2cf7396a23c9956d099d883a91d9d62ce7455960a85bc9df776978160bb1d6c5'
//]
$token = $csrf->getToken();

echo '<form action="http://www.example.com/validateForm" method="POST">
<input type="hidden" name="'.$token['name'].'" value="'.$token['value'].'" />
<input type="text" name="important_data" value="put data here"/>
<input type="submit" value="Submit" />
</form>';
```

Get timed token:
```php
//return token as array that appear like this
//random token name
//token expires after 10 munites (600 seconds)
//32 byte token
//[
//  'name' => string 'csrf_96b74c2ae8a1e126'
//  'value' => string '194c505365b77a4ee0f0d9015473b97fa632bad26dce381ead04e0d05bec3e0d'
//  'time' => int 1606504740
//]
$token = $csrf->getTimedToken();

echo '<form action="http://www.example.com/validateForm" method="POST">
<input type="hidden" name="'.$token['name'].'" value="'.$token['value'].'" />
<input type="text" name="important_data" value="put data here"/>
<input type="submit" value="Submit" />
</form>';
```

Get hidden input:
```php
echo '<form action="http://www.example.com/validateForm" method="POST">'.
$csrf->getHiddenInput()
.'<input type="text" name="important_data" value="put data here"/>
<input type="submit" value="Submit" />
</form>';
```
> **Note:** `getHiddenInput()` method removed in version 1.2.0.

## Validate token
Token validation is a transparent process, only need to pass request data to `validate()` method.
```php
//work with $_POST, $_REQUEST, $_COOKIE
//return true on success, false on failure
$csrf->validate($_REQUEST);
```

`$_GET` superglobal is not mentioned because data change on server, should be done through HTTP POST method.

## Storage cleaning
When user load a page with a form that use CSRF and after never sends it or simply change the page, 
CSRF token remains in the storage. In this case php session file can grow a lot.

For prevent session file fat, could be used two methods, `garbageCollector()` and `clean()`.

All methods have one parameter, it indicates the number of preserved tokens and all methods start to delete tokens from the oldest in memory.

If a CSRF token is generated on every request and a big value is used in constructor for storage (ex. `new CsrfGuard(128, 32)`), 
it could be however necessary free the storage.

> **Note:** `garbageCollector()` and `clean()` methods are available since version 1.3.0.

### garbageCollector()
This method remove old tokens only where the maximun capacity in storage is reached.

Get the token.
```php
session_start();

$csrf = new CsrfGuard(32);
$token = $csrf->getToken();

//int 1
var_dump(count($_SESSION['CSRF']));

//2 passed as parameter means that method preserve 2 latest token inside the storage
$csrf->garbageCollector(2);

//int 1
var_dump(count($_SESSION['CSRF']));
```

If the token isn't validate it remains in session storage and next call of `getToken()` make session file bigger.

After 32 requests without `validate()` usage, the storage reach maximun declared 
capacity, `garbageCollector()` method clean the storage.
```php
session_start();

$csrf = new CsrfGuard(32);
$token = $csrf->getToken();

//int 32
var_dump(count($_SESSION['CSRF']));

//2 passed as parameter means that method preserve 2 latest token inside the storage
$csrf->garbageCollector(2);

//int 2
var_dump(count($_SESSION['CSRF']));
```

### clean()
This method remove old tokens every time is called.
Get the token.
```php
session_start();

$csrf = new CsrfGuard(32);
$token = $csrf->getToken();

//int 1
var_dump(count($_SESSION['CSRF']));

//2 passed as parameter means that method preserve 2 latest token inside the storage
$csrf->clean(2);

//int 1
var_dump(count($_SESSION['CSRF']));
```

After only 3 request without `validate()` usage, `clean()` method clean the storage.
```php
session_start();

$csrf = new CsrfGuard(32);
$token = $csrf->getToken();

//int 3
var_dump(count($_SESSION['CSRF']));

//2 passed as parameter means that method preserve 2 latest token inside the storage
$csrf->clean(2);

//int 2
var_dump(count($_SESSION['CSRF']));
```
