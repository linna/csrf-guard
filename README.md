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

# Token types

> **Note:** Storage it's intended that the data about token or the token is stored in session.

The package provides three types of token:
- Encryption-based CSRF token
- HMAC-based CSRF token
- Synchronizer CSRF token

## Encryption-based token
Encryption-based CSRF token is a token that is the result of a cryptographic algorithm, some data is encrypted using a 
secret key only known from the server .The implementation in this library uses `libsodium` aead contruction 
`XChaCha20-Poly1305`. The token has expire time and require local storage.

The token security depends from:
- secret key storage
- strength of `XChaCha20-Poly1305`

This token is valid until validated or until it expires. It's possible to select a length of the token. The length of 
the token doesn't affect the storage used.

The key used for the engryption is generated for every session, the nonce for every token.

## HMAC-based token
HMAC-based CSRF token is a token that is computed by applying an HMAC function to some data and a secret key that is 
only known from the server. The implementation in this library uses php `hash_hmac` with the `sha3-384` algorithm.
This type of token deosn't require local storage and it has an expire time.

The token security depends from:
- secret key storage
- strength of `sha3-384`

This token is valid until expires and can be validate more times. Also has fixed length and it's not possible to change 
it to obtain a shorter or longer token.

The key used to authenticate is fully managed by the user of the library.

## Synchronizer token
The Synchronizer CSRF token is a token randomly generated. This library uses php `random_bytes`. The token has expire 
time and require local storage.

The token security depends from:
- the length of the token

This token is valid until validated or until it expires. It's possible to select a length of the token. The length of 
the token affects the storage used.


# Usage

> **Note:** Session must be started before you create the instance of a provider, 
if no a `SessionNotStartedException` will be throw, this is not true if you use the `HmacTokenProvider`.

## Get started

How to get and validate a token using few lines of code.

### Generate a provider
```php
//start the session
\session_start();

//generate token provider
$provider = ProviderSimpleFactory::getProvider();
```

### Get a token
```php
//previous php code

//get a token from provider
$token = $provider->getToken();
```

### Validate it
```php
//previous php code

//true if valid, false otherwise
$isValid = $provider->validate($token);
```

## Provider configuration

The `ProviderSimpleFactory::getProvider()` static method has two parameters:
- the provider
- options for the provider

### EncryptionTokenProvider config

| Options     | Default Value | Unity   | Range   | Mandatory |
|-------------|---------------|---------|---------|-----------|
| expire      | 600           | seconds | 0-86400 | no        |
| storageSize | 10            | tokens  | 2-64    | no        |
| tokenLength | 16            | bytes   | 16-128  | no        |

Example of usage:
```php
//start the session
\session_start();

//get specific encryption token provider
$provider = ProviderSimpleFactory::getProvider(
    provider: EncryptionTokenProvider::class, // specific token provider
    options: [                                // options
        'expire' => 3600,                     // token expire in 3600 seconds, 1 hour
        'storageSize' => 16,                  // provider can store maximum 1 key and 16 nonces per session,
        'tokenLength' => 16                   // desidered token length in bytes, token will be used as plaintext and not stored
    ]
);
```

### HmacTokenProvider config

| Options     | Default Value | Unity   | Range   | Mandatory |
|-------------|---------------|---------|---------|-----------|
| value       | //            |         |         | yes       |
| key         | //            |         |         | yes       |
| expire      | 600           | seconds | 0-86400 | no        |


Example of usage:
```php
//get specific hmac token provider
$provider = ProviderSimpleFactory::getProvider(
    provider: HmacTokenProvider::class,             // specific token provider
    options: [                                      // options
        'value' => 'value will be hashed in token', // value will be hashed in token
        'key' => 'key_to_authenticate'              // key to authenticate the hash
    ]
);
```

### SynchronizerTokenProvider config

| Options     | Default Value | Unity   | Range   | Mandatory |
|-------------|---------------|---------|---------|-----------|
| expire      | 600           | seconds | 0-86400 | no        |
| storageSize | 10            | tokens  | 2-64    | no        |
| tokenLength | 32            | bytes   | 16-128  | no        |

Example of usage:
```php
//start the session
\session_start();

//get specific syncronizer token provider
$provider = ProviderSimpleFactory::getProvider(
    provider: SynchronizerTokenProvider::class, // specific token provider
    options: [                                  // options
        'expire' => 3600,                       // token expire in 3600 seconds, 1 hour
        'storageSize' => 16,                    // provider can store maximum 16 token per session,
        'tokenLength' => 32                     // desidered token length in bytes, token will be the double in chars
    ]
);
```