# ngx_http_auth_jwt_module
nginx c module to protect resources using jwt.

This modules is heavenly inspired by the nginx original http_auth_jwt_module. Unfortunately this module is only available in the commercial subscription. This is a replacement that can be used by compiling it with the open source nginx.

## Dependencies

This module depends on openssl, libjwt and jansson C libraries.

## Compile

In order to compile, dowload source code for nginx and this repo. From the nginx folder, issue the following command.

```
./configure --with-http_ssl_module --with-http_auth_request_module --add-module=../ngx_http_auth_jwt_module
```

## Usage

There are few directives that can be used in the configuration file in order to activate this module.

### auth_jwt

The usage of this directive is identical of the one on the original nginx PLUS http_auth_jwt_module:

```
Syntax: auth_jwt string [token=$variable] | off ;
Default: auth_jwt off;
Context: http, server, location
```
the optional token parameter takes a variable that contains the JSON Web Token. If not present the module expects the JSON Web Token to be passsed in the Authorization header as Bearer Token. Since token can be assigned to a variable, the JWT can be passed as a cookie or a query string. Example of usage:

```
auth_jwt "Reserved site" token=$cookie_myjwtcookie
```

The reserved value off disable the jwt protection.

### auth_jwt_key_file

This directive is used to specify the file hosing the key. This must be a certificate in case JWT is encrypted using an asymmetric key encryption (RS256 for example) or the shared secret in case JWT is encrypted using a symmetric algorithm (HS256 for example).

```
Syntax: auth_jwt_key_file file;
Default: -
Context: http, server, location
```

### auth_jwt_alg

This directive is used to specify which algorithm the server expects to receive in the JWT. As suggested by [Auth0](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) letting the creator ot the JWT to choose the encryption algorithm can leed to critical vulnerabilities.
The specification of the algorithm is mandatory, and NONE is not accepted as a valid one.

```
Syntax: auth_jwt_alg HS256 | HS384 | HS512 | RS256 | RS384 | RS512 | ES256 | ES384 | ES512
Default: -
Context: http, server, location
```

