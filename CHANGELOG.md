
# Linna Csrf Guard Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/) 
and this project adheres to [Semantic Versioning](http://semver.org/).

## [Unrelased][v1.2.0](https://github.com/linna/csrf-guard/compare/v1.1.2...v1.2.0) - 2018-XX-XX

### Changed
* Minimun PHP version: 7.1
* Enhance generating token from [Pull Request #7](https://github.com/linna/csrf-guard/pull/7)

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
