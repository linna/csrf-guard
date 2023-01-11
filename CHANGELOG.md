
# Linna Csrf Guard Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unrelased][v2.0.0](https://github.com/linna/csrf-guard/compare/v1.4.0...b2.0.0) - 202X-XX-XX

### Added
* `Linna\CsrfGuard\Exception` namespace
* `Linna\CsrfGuard\Exception\BadExpireException` exception
* `Linna\CsrfGuard\Exception\BadStorageSizeException` exception
* `Linna\CsrfGuard\Exception\BadTokenLenghtException` exception
* `Linna\CsrfGuard\Exception\BadExpireTrait` trait
* `Linna\CsrfGuard\Exception\BadStorageSizeTrait` trait
* `Linna\CsrfGuard\Exception\BadTokenLenghtTrait` trait
* `Linna\CsrfGuard\Exception\ExceptionBoundary` class
* `Linna\CsrfGuard\ProviderSimpleFactory` class
* `Linna\CsrfGuard\Provider` namespace
* `Linna\CsrfGuard\Provider\EncryptionTokenProvider` class
* `Linna\CsrfGuard\Provider\HmacTokenProvider` class
* `Linna\CsrfGuard\Provider\SynchronizerTokenProvider` class
* `Linna\CsrfGuard\Provider\TokenProviderInterface` interface

### Changed
* namespace of the packet is now `Linna\CsrfGuard`

### Removed
* `Linna\CsrfGuard` class


## [v1.4.0](https://github.com/linna/csrf-guard/compare/v1.3.2...v1.4.0) - 2020-11-28

### Added
* PHP 8.0 support

### Changed
* `getTimedToken()` now `$ttl` parameter has a default value of 600 (seconds)
* `cleanStorage()` now `$preserve` parameter has a default value of 0 (clean all)
* Minor code optimization
* Minimun PHP version: 7.4

## [v1.3.2](https://github.com/linna/csrf-guard/compare/v1.3.1...v1.3.2) - 2020-02-11

### Added
* backslash in front of native functions
* PHP 7.3 support

## [v1.3.1](https://github.com/linna/csrf-guard/compare/v1.3.0...v1.3.1) - 2018-08-26

### Changed
* `RuntimeException` message for instance created without start session
* Tests updated as [Issue #10](https://github.com/linna/csrf-guard/issues/10)

## [v1.3.0](https://github.com/linna/csrf-guard/compare/v1.2.0...v1.3.0) - 2018-08-25

### Changed
* Tests updated

### Added
* Token storage clean system as [Issue #9](https://github.com/linna/csrf-guard/issues/9)
* `garbageCollector()` method as part of token storage clean system
* `clean()` method as part of token storage clean system

## [v1.2.0](https://github.com/linna/csrf-guard/compare/v1.1.2...v1.2.0) - 2018-08-13

### Changed
* Minimun PHP version: 7.1
* Enhance generating token from [Pull Request #7](https://github.com/linna/csrf-guard/pull/7)
* Tests updated

### Removed
* `getHiddenInput()` method

## [v1.1.2](https://github.com/linna/csrf-guard/compare/v1.1.1...v1.1.2) - 2017-09-08

### Added
* Token deletion after validation
* Tests updated

## [v1.1.1](https://github.com/linna/csrf-guard/compare/v1.1.0...v1.1.1) - 2017-08-21

### Changed
* Internal token check methods refactor
* Tests updated

## [v1.1.0](https://github.com/linna/csrf-guard/compare/v1.0.0...v1.1.0) - 2017-08-20

### Added
* `getTimedToken()` method for expiring tokens

### Changed
* `validate()` naw can validate for timed tokens
* Tests updated
* Internal methods refactor

### Deprecated
* `getHiddenInput()` method

### Fixed
* `private $session;` docblock

## [v1.0.0](https://github.com/linna/csrf-guard/compare/v1.0.0...master) - 2017-07-26

### Added
* `RuntimeException` throw if you try to create `CsrfGuard` instance before start session
* Initial commit, class and tests

### Fixed
* `CHANGELOG.md` links url
