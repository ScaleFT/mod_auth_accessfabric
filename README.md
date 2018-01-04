# mod_auth_accessfabric

[![Build Status](https://travis-ci.org/ScaleFT/mod_auth_accessfabric.svg?branch=master)](https://travis-ci.org/ScaleFT/mod_auth_accessfabric)

`mod_auth_accessfabric` is an Apache 2.4.x module for authenticating requests from the ScaleFT Access Fabric.  Requests are authenticated by validating the contents of the `Authenticated-User-JWT` header against a list of trusted signing JWKs from the ScaleFT Platform.

# What's New

## 1.0.2 (in development)

## 1.0.1

- Add autotools based build (classic `./configure && make && make install`) [#4](https://github.com/ScaleFT/mod_auth_accessfabric/pull/4)
- Fix bug in updating the JWKs from cache [#5](https://github.com/ScaleFT/mod_auth_accessfabric/pull/5)

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

- Apache 2.4.x with `apxs` available. (Found in `apache2-dev` for Debian-based distros or `httpd-devel` on RPM-based distros)
- [libxjwt](https://github.com/ScaleFT/libxjwt): Library for validating JWTs
- [libcurl](https://curl.haxx.se/libcurl/): Library for fetching remote JWKs
- [OpenSSL](https://www.openssl.org/): `libxjwt` uses EC and EVP APIs.
- [Jansson](http://www.digip.org/jansson/): JSON Parser used by `libxjwt`

## Building

```
./configure --with-xjwt=/usr/local
make
sudo make install
```

### Build Flags

- `--with-apxs=APXS`: Absolute path name of apxs executable
- `--with-openssl=DIR`: Root of the OpenSSL installation
- `--with-jansson=DIR`: Root of the Jansson installation
- `--with-curl=DIR`: Root of the curl installation
- `--with-xjwt=DIR`: Root of the xjwt installation

# License

`mod_auth_accessfabric` is licensed under the Apache License Version 2.0. See the [LICENSE file](./LICENSE) for details.
