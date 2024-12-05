# tlshack
Copy of [golang-crypto-tls](https://github.com/mordyovits/golang-crypto-tls) for ancient crypto (like TLS_DH_anon_WITH_AES_256_GCM_SHA384) used at some point in conserver.

# golang-crypto-tls
Fork of golang 1.8.1 crypto/tls to add DHE, PSK, DHE_PSK, RSA_PSK, and DH_anon ciphersuites

# WARNING
Some ciphersuites that this package implements were left unimplemented in the standard golang package for a reason!  Those ciphersuites should only be used if you understand why you are using them.  For example:

1. DH_anon ciphersuites provide no authentication and are vulnerable to a MITM attack.
2. DHE ciphersuites are slower than ECDHE ciphersuites.

For your protection, every ciphersuite added in this package is not enabled by default.  To use them you must explicitly name them in the CipherSuites setting in your tls.Config.

# Added Ciphersuites

This package implements every standard TLS key exchange mechanism except SRP and ECDHEPSK (no one cares about FORTEZZA).  If you need either of those, let me know; ECDHEPSK is simple to add, SRP less so.

The following 32 ciphersuites are added in this package:
## DHE_RSA
* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
* TLS_DHE_RSA_WITH_AES_128_CBC_SHA
* TLS_DHE_RSA_WITH_AES_256_CBC_SHA
* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

## DH_anon
* TLS_DH_anon_WITH_AES_128_GCM_SHA256
* TLS_DH_anon_WITH_AES_256_GCM_SHA384
* TLS_DH_anon_WITH_AES_128_CBC_SHA
* TLS_DH_anon_WITH_AES_256_CBC_SHA
* TLS_DH_anon_WITH_AES_128_CBC_SHA256
* TLS_DH_anon_WITH_AES_256_CBC_SHA256

## RSA
* TLS_RSA_WITH_AES_256_CBC_SHA256

## RSA_PSK
* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
* TLS_RSA_PSK_WITH_AES_128_CBC_SHA
* TLS_RSA_PSK_WITH_AES_256_CBC_SHA
* TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256

## DHE_PSK
* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
* TLS_DHE_PSK_WITH_AES_128_CBC_SHA
* TLS_DHE_PSK_WITH_AES_256_CBC_SHA
* TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256

## PSK
* TLS_PSK_WITH_AES_128_CBC_SHA256
* TLS_PSK_WITH_AES_128_CBC_SHA
* TLS_PSK_WITH_AES_256_CBC_SHA
* TLS_PSK_WITH_AES_128_GCM_SHA256
* TLS_PSK_WITH_AES_256_GCM_SHA384
* TLS_PSK_WITH_CHACHA20_POLY1305_SHA256

# How to use this package
Since it's a fork of a built-in package, there are a few ways to use it, none perfect.  Here are the options:

## Replace the default package in $GOROOT
This is the simplest option, but it requires modifying your Go installation:

1. cd $GOROOT/src/crypto
2. mv tls tls.bak
3. git clone https://pathtothis/golang-crypto-tls tls

Then rebuild with go build -a

## Vendor it

git clone it into a vendor/crypto/tls directory

Works great, but requires vendoring a few more packages.

## Import it under an alias

import (tls "pathtothis/tls)

Downside: crypto has an internal package, so you'll need to manually duplicate that to a vendor directory.
