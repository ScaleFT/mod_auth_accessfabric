# mod_auth_accessfabric

[![Build Status](https://travis-ci.org/ScaleFT/mod_auth_accessfabric.svg?branch=master)](https://travis-ci.org/ScaleFT/mod_auth_accessfabric)

`mod_auth_accessfabric` is an Apache 2.4.x module for authenticating requests from the ScaleFT Access Fabric.  Requests are authenticated by validating the contents of the `Authenticated-User-JWT` header against a list of trusted signing JWKs from the ScaleFT Platform.

# What's New

## 1.0.0

Initial open source release.

# Configuration

`mod_auth_accessfabric` registers a new `AuthType` backend, `AccessFabric`.  When enabled, the module checks for a signed header from the ScaleFT Access Fabric in the `Authenticated-User-JWT` header.

## Minimal configuration

The `AuthAccessFabricAudience` configuration option must be set to the ScaleFT Application URL.  This represents the authorization scope for a request from a user.

In the ScaleFT dashboard, you can create an Access Fabric Application under a Project. Get the `APPLICATION URL` from the ScaleFT dashboard, and replace `calm-cerberus-0352.accessfabric.com` in the example below with your `APPLICATION URL`:

```
LoadModule auth_accessfabric_module /usr/lib/apache2/modules/mod_auth_accessfabric.so

<Location "/">
  AuthType AccessFabric
  AuthAccessFabricAudience "https://calm-cerberus-0352.accessfabric.com"
  Require valid-user
</Location>
```

## Logging Extensions: Subject IDs and and E-Mail address

On sucessful authentication, `mod_auth_accessfabric` sets the request notes `auth_accessfabric_sub` and `auth_accessfabric_email` with validated values from the JWT.  These can be added to your access logs:

```
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %{auth_accessfabric_sub}n \"%{auth_accessfabric_email}n\"" extended-af
CustomLog "logs/access_log" extended-af
```


## Dependencies

- Apache 2.4.x with `apxs` available.
- [libxjwt](https://github.com/ScaleFT/libxjwt): Library for validating JWTs
- [libcurl](https://curl.haxx.se/libcurl/): Library for fetching remote JWKs
- [OpenSSL](https://www.openssl.org/): `libxjwt` uses EC and EVP APIs.
- [Jansson](http://www.digip.org/jansson/): JSON Parser used by `libxjwt`
- (build-only) c89 compiler
- (build-only) scons

## Building

```
scons APXS=/usr/bin/apxs with_xjwt=/usr/local
scons install APXS=/usr/bin/apxs with_xjwt=/usr/local
```

### Build Variables

- `APXS`: Path to the `apxs` command
- `with_jansson`: Prefix to Jansson installation
- `with_openssl`: Prefix to OpenSSL installation
- `with_xjwt`: Prefix to libxjwt installation
- `with_curl`: Prefix to libcurl installation

# License

`mod_auth_accessfabric` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.
