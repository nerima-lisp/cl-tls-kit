# cl-tls-kit

Common Lisp building blocks for TLS 1.3 (RFC 8446), X.509, and the TLS
portion of QUIC (RFC 9001). This project does not implement a TLS 1.2
protocol stack. The TLS 1.3 client only detects the TLS 1.2/1.1 downgrade
sentinels in a TLS 1.3 ServerHello; it does not negotiate or fall back to
TLS 1.2.

The library provides strict DER and unencrypted PEM parsing, X.509 parsing,
certificate-chain checks, the TLS 1.3 record and handshake data types, the
TLS 1.3 key schedule, callback-driven client boundaries, and QUIC CRYPTO
stream boundaries. Cryptographic hashing, signing, verification, key
exchange, and AEAD are provider responsibilities. `cl-crypto-kit` is an
optional weak dependency used by the provider-backed checks and RFC 8448
vector test.

Certificate verification checks validity, issuer chains, basic constraints,
key usage, extended key usage, name constraints, trust anchors, and SAN
hostname matching. A client verification callback that returns false or
signals a condition is reported as `tls-client-verification-error`; its
`tls-client-verification-certificate` and `tls-client-verification-cause`
readers identify the certificate and underlying cause. The lower-level
verification API signals conditions such as `certificate-expired`,
`certificate-hostname-mismatch`, `untrusted-root`, `bad-signature`, and
`invalid-certificate-chain`.

RSA-PSS certificate signatures support SHA-256, SHA-384, and SHA-512. Their
parameters must use the same hash for MGF1, a salt length equal to the digest
length, and trailer field 1. Certificate parsing rejects a mismatch between
the TBSCertificate and outer signature AlgorithmIdentifier encodings.

OCSP and CRL processing are intentionally out of scope. Certificate parsing
and chain checks do not fetch or evaluate revocation status, and there are no
OCSP or CRL APIs.

## TLS 1.3 negotiation

The exported cipher-suite constants and helpers cover these RFC 8446 suites:

- `TLS_AES_128_GCM_SHA256` (`0x1301`)
- `TLS_AES_256_GCM_SHA384` (`0x1302`)
- `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)
- `TLS_AES_128_CCM_SHA256` (`0x1304`)

The implementation passes supported-group IDs through ClientHello and key
share helpers. The built-in client defaults are X25519 (`0x001d`) in
`tls-client-make-client-hello` and X25519 plus secp256r1 (`0x0017`) in the
standalone handshake driver. A crypto/provider integration must supply the
actual key generation and shared-secret operations.

SNI and ALPN are optional ClientHello extensions. `make-tls-client` accepts
`hostname` and `alpn-offered`; `tls-client-make-client-hello` encodes them
with `encode-sni-extension` and `encode-alpn-extension`. The driver accepts
`hostname` and `alpn` and includes the same extensions. The negotiated ALPN
value is available through `tls-client-alpn` after provider input is applied,
or `tls13-client-driver-negotiated-alpn` for the handshake driver.

## Client and stream boundaries

### Callback client

`make-tls-client` is a provider-defined boundary, not a complete handshake
implementation. Its `provider` can be a function used for all three operations
below, or a property list selecting a separate function for each:

- `:client-hello` receives `(client)` and returns a `tls13-client-hello`, or a
  plist with that object under `:message` on the initial call. A retry call
  requires the ClientHello object directly.
- `:handshake` receives `(client input)`, where input is `:start` or the input
  supplied to `tls-client-step` (encoded handshake bytes are decoded first),
  and returns a result plist.
- `:key-update` receives `(client request)`, where request is 0 or 1, and
  returns a result plist.

Result plists can supply an `:outgoing` list of encoded handshake messages or
`(type . payload)` pairs, `:peer-certificate` for verification, `:alpn`, and
`:state` (`:awaiting-input`, `:connected`, or `:failed`). The client validates
handshake ordering before applying provider
input. `tls-client-connect` only starts the handshake; the application must
drive `tls-client-step` until `tls-client-state` is `:connected`.

`transport-read` receives `(client)` and returns an encoded TLS record or nil.
`transport-write` receives `(client bytes)`; handshake output is encoded
handshake bytes, not TLS records. For connected application I/O,
`record-protect` receives `(client plaintext)` and returns bytes for the
writer; `record-unprotect` receives `(client record)` and returns the value
that `tls-client-read` returns. Without these adapters, data passes through
unchanged. Control records are processed only when unprotect returns a
`tls-plaintext`. A provider plist can additionally contain `:close-notify`,
which receives `(client)` and returns an encoded alert record or nil.
`transport-close` receives `(client)`.

`tls-client-read` and `tls-client-write` require a connected client.
`make-tls-client-over-tcp` supplies blocking SBCL socket I/O, but does not
supply the handshake provider or record adapters. Other implementations must
provide transport callbacks directly.

### TLS 1.3 handshake driver

`make-tls13-client-driver` is the more prescriptive callback-driven TLS 1.3
handshake sequence. After loading `cl-crypto-kit` with ASDF,
`make-cl-crypto-kit-provider` creates the required `tls13-crypto-provider`
for hashing, HKDF, HMAC, and AEAD. Key exchange is a separate plist:
`:generate` receives `(group-id)` and returns private key and public octets as
two values; `:shared-secret` receives `(group-id private-key peer-public-octets)`
and returns shared-secret octets.

The optional `on-send` callback receives `(driver handshake-bytes)` as a
notification. It is not the socket writer: the driver separately wraps and
protects these bytes as TLS records. It sequences ClientHello,
HelloRetryRequest, ServerHello, EncryptedExtensions, Certificate,
CertificateVerify, and Finished, rejecting messages out of sequence before
adding them to the transcript. Its `verify` argument defaults to `:required`;
`:optional` applies the same certificate-chain, hostname, and trust policy.
Supply `trust-anchors` explicitly or let the driver load the platform trust
store. `verify nil` skips those certificate-policy checks, but the driver
still parses the peer certificate and cryptographically verifies
CertificateVerify. Signature verification uses `verify-signature`, called as
`(scheme public-key input signature)` and returning a boolean, or the loaded
crypto implementation when omitted. This is separate from the key-schedule
provider. `verify-certificate-verify` receives the parsed message as a hook;
it cannot replace mandatory signature verification. Use `verify nil` only
for deliberately unauthenticated test connections.

`transport-read` receives `(driver)` and returns one encoded TLS record or nil;
`transport-write` receives `(driver record-bytes)`; `transport-close` receives
`(driver)`. `make-tls13-client-driver-over-tcp` supplies these callbacks on
SBCL. `tls13-client-driver-connect` blocks until connected and returns the
driver. `tls13-client-driver-write` accepts application octets.
`tls13-client-driver-read-record` returns application data as `tls-plaintext`;
use `tls-plaintext-fragment` for its bytes. It returns nil for a consumed
handshake, KeyUpdate, compatibility CCS, peer close_notify, or an already
closed driver. Transport EOF before close_notify signals an error, so nil
from this API does not by itself mean transport EOF.

`tls13-client-driver-close-notify-received-p` distinguishes a peer's
close_notify from transport EOF. Receiving close_notify marks the driver
closed and stops application-data reads. `tls13-client-driver-close` closes
the transport once, including when sending the local close_notify fails;
calling it again does not send another alert or close the transport again.

The lower-level `make-tls-client` boundary requires a
`:verify-certificate` callback whenever a peer certificate is received. It
receives `(certificate)` and must return true; a missing callback or false
result rejects the certificate.

In the chain verification API, a caller-provided trust anchor is explicitly
trusted and is not revalidated as an issued certificate, so its
CA constraint, key usage, and self-signature are outside this policy. All
certificates below the trust anchor remain subject to chain, signature,
validity, and usage checks; the anchor's validity interval is still checked.

## QUIC TLS boundary

`make-quic-tls-boundary` handles TLS handshake bytes carried in QUIC CRYPTO
streams. Its contract levels are `:initial`, `:handshake`, and `:application`;
the former `:1-rtt` name remains accepted and is normalized to `:application`
for compatibility. `:0-rtt` is rejected because this boundary does not expose
0-RTT TLS secrets. It supports sequential input and RFC 9001 offset-aware
`feed-crypto` input,
tracks the TLS transcript and HelloRetryRequest state, and forwards emitted
handshake bytes through `on-crypto`. `on-secret` receives established
encryption-level read/write secrets without deriving keys or protecting QUIC
packets. A TLS handshake/provider that has validated the negotiated values
calls `quic-tls-boundary-emit-cipher-suite` and
`quic-tls-boundary-emit-alpn`; those values are also available through
`quic-tls-boundary-cipher-suite` and `quic-tls-boundary-alpn`. The boundary
does not claim to derive secrets or perform cipher-suite/ALPN negotiation.
Transport parameters are supplied as opaque RFC 9001 bytes and can be added to
ClientHello from a client boundary or EncryptedExtensions from a server
boundary. `quic-tls-boundary-send-message` and
`quic-tls-boundary-receive` are the public message output/input boundary;
`quic-tls-boundary-feed-crypto` additionally accepts CRYPTO offsets. They carry
TLS handshake bytes directly in CRYPTO data and do not pass through the TLS
record layer. The exported `cl-tls-kit` package
(also nicknamed `tls-kit`) is the package a QUIC implementation such as
`cl-quic-kit` can call.

This boundary does not implement QUIC packets, CRYPTO frame scheduling, packet
protection, key derivation, or a TLS provider. It also does not provide a TCP
transport or an end-to-end QUIC connection; the QUIC implementation owns those
layers and supplies CRYPTO offsets and callbacks. SNI and ALPN are TLS 1.3
ClientHello extensions built with `encode-sni-extension`,
`encode-alpn-extension`, and `make-tls13-client-hello-extensions`; QUIC
transport parameters are a separate extension and are not SNI or ALPN.

## Public API

The `cl-tls-kit` package, also nicknamed `tls-kit`, exports DER and PEM helpers,
certificate verification, TLS 1.3 record/handshake/key-schedule APIs, callback
clients, the handshake driver, and QUIC boundaries. The separate
`cl-tls-kit.x509` package exports `parse-x509-certificate`,
`parse-certificate`, `parse-certificate-der`, and the `x509-certificate-*`
readers. Public API names and documentation are English. The project is MIT
licensed.
