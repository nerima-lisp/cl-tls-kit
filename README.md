# cl-tls-kit

Common Lisp building blocks for TLS 1.3 (RFC 8446), X.509, and the TLS
portion of QUIC (RFC 9001). This project does not implement a TLS 1.2
protocol stack. The TLS 1.3 client driver only detects the TLS 1.2/1.1 downgrade
sentinels in a TLS 1.3 ServerHello; it does not negotiate or fall back to
TLS 1.2.

The library provides strict DER and unencrypted PEM parsing, X.509 parsing,
certificate-chain checks, the TLS 1.3 record and handshake data types, the
TLS 1.3 key schedule, callback-driven client boundaries, and QUIC CRYPTO
stream boundaries.

Certificate verification checks validity, issuer chains, basic constraints,
key usage, extended key usage, name constraints, trust anchors, and SAN
hostname matching. The lower-level verification API signals conditions such
as `certificate-expired`,
`certificate-hostname-mismatch`, `untrusted-root`, `bad-signature`, and
`invalid-certificate-chain`.

Certificate parsing and chain checks do not fetch or evaluate revocation
status, and there are no OCSP or CRL APIs.

## TLS 1.3 negotiation

The exported cipher-suite constants and helpers support these RFC 8446 suites:

- `TLS_AES_128_GCM_SHA256` (`0x1301`)
- `TLS_AES_256_GCM_SHA384` (`0x1302`)
- `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)
- `TLS_AES_128_CCM_SHA256` (`0x1304`)

`make-tls13-client-driver` defaults to offering AES-128-GCM, AES-256-GCM, and
ChaCha20-Poly1305 in that order. It also accepts AES-128-CCM when
`:cipher-suites` includes it.

The lower-level ClientHello and key-share helpers pass supported-group IDs
through unchanged. `tls-client-make-client-hello` defaults to X25519 (`0x001d`).
The `make-tls13-client-driver` constructor accepts `:supported-groups`, which
defaults to X25519 followed by P-256 (`secp256r1`, `0x0017`). It sends an initial
key share for the first group in that list, X25519 by default. If the server
requests a different offered group in HelloRetryRequest, it generates a share
for that group. Without `:key-exchange`, the driver uses the `crypto-kit`
package supplied by the optional `cl-crypto-kit` ASDF system; load that system
for this default path. A supplied `:key-exchange` plist replaces the built-in
functions and must provide
`:generate` and `:shared-secret` callbacks for every group in
`:supported-groups`. Callers using the lower-level helpers must provide their
own key generation and shared-secret operations.

SNI and ALPN are optional ClientHello extensions. `make-tls-client` accepts
`hostname` and `alpn-offered`; `tls-client-make-client-hello` encodes them
with `encode-sni-extension` and `encode-alpn-extension`. The driver accepts
`hostname` and `alpn` and includes the same extensions. When present,
`alpn-offered` and `alpn` are non-empty lists of protocol strings to offer. At
the lower-level boundary, `tls-client-alpn` is updated from the provider's
`:alpn` result when present and from an ALPN extension in `EncryptedExtensions`.
The provider result is applied after the decoded message, so it takes
precedence when both supply a value in one step. The driver exposes the
selected protocol through `tls13-client-driver-negotiated-alpn` after
processing `EncryptedExtensions`.

## Client and stream boundaries

`make-tls-client` is a boundary around callbacks, not an independent
provider-neutral handshake implementation. Its `provider` argument can be a
single function used for `:client-hello`, `:handshake`, and `:key-update`, or a
property list of named callbacks. A single function is called with the client
to create ClientHello, with the client and `:start` or a decoded handshake
message for handshake steps, and with the client and a `0` or `1` key-update
request. `0` means the peer need not respond; `1` asks it to send a KeyUpdate
response. A ClientHello callback returns a `tls13-client-hello` or a plist with
that object under `:message`; handshake and key-update callbacks can return a
result plist. `:transcript` appends bytes; `:message` advances the expected
message and `:wire` appends its encoding. `:server-random` is checked against
`:version` (default `:tls-1.3`); `:peer-certificate` triggers verification;
`:alpn` records the selection; `:key-schedule-event` invokes the key-schedule
callback; `:outgoing` sends handshake messages; and `:unexpected-message`
signals an error. These entries are optional; the provider returns the updates
its handshake step needs. Named callbacks use the same arguments and return
contracts. Only a property list can provide `:close-notify`; that callback
receives the client and may return an encoded TLS record. `transport-read`
receives the client and returns one encoded TLS record or `nil`;
`transport-write` receives the client and encoded bytes.

`tls-client-read` and `tls-client-write` operate only after the client is
connected. `make-tls-client-over-tcp` supplies a blocking SBCL TCP stream
adapter; other implementations must provide transport callbacks directly.

`make-tls13-client-driver` sequences handshake messages and transcript/key
schedule progress. Its separate `:provider` argument takes a
`tls13-crypto-provider` instance for hash, HKDF, HMAC, and AEAD operations;
`make-cl-crypto-kit-provider` returns one backed by `cl-crypto-kit`. The
optional `on-send` callback receives encoded handshake message bytes before
TLS record framing. With a custom transport, `transport-read` receives the
driver and returns an encoded TLS record or `nil`; `transport-write` receives
the driver and the encoded record. The driver processes ServerHello,
EncryptedExtensions, Certificate, CertificateVerify, and Finished after
ClientHello; HelloRetryRequest can occur between ClientHello and ServerHello
when the server requests a different offered group. The driver validates the
peer certificate chain against explicit `trust-anchors`. Without them, it uses
the first configured source: `SSL_CERT_FILE`, then `NIX_SSL_CERT_FILE`. If
neither is set, macOS uses the System Roots Keychain, while other platforms use
the first existing path among these, in order: `/etc/ssl/cert.pem`,
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`,
`/etc/ssl/ca-bundle.pem`, and `/etc/ssl/certs`. An unreadable selected source
raises an error instead of falling through to the next source. macOS user and
administrator trust settings are not loaded. The driver checks the certificate
hostname only when `hostname` is set; it validates the chain either way. The
`verify-signature` callback receives the scheme, public key, signed bytes, and
signature, and must return true for valid signatures. The driver uses it for
certificate-chain signatures and `CertificateVerify`. Supply `transport-read`
and `transport-write` callbacks, or use
`make-tls13-client-driver-over-tcp`, which opens a blocking SBCL TCP stream.
`tls13-client-driver-connect` blocks until the handshake completes;
`tls13-client-driver-write`, `tls13-client-driver-close`, and
`tls13-client-driver-key-update` write application data, close the connection,
and update the write traffic secret.

RSA-PSS certificate signatures with `rsaEncryption` (`RSAE`) public keys
support SHA-256, SHA-384, and SHA-512. `RSASSA-PSS` subject public keys are not
supported. MGF1 must use the same digest, the salt length must equal the digest
length, and the trailer field must be 1. The signature AlgorithmIdentifiers in
the certificate and its TBSCertificate must match, including their parameters.

For client resumption, create a store with `make-tls13-ticket-store` and pass it
as `:ticket-store` to client drivers. `clear-tls13-ticket-store` removes all
currently stored tickets and zeroizes each stored ticket PSK.

After `tls13-client-driver-connect`, use
the exported `tls13-client-driver-read-application-data` to read without
inspecting the driver's state. It returns `(values :data octets)` for application data,
`:would-block` when `make-tls13-client-driver`'s custom `transport-read`
callback returns that marker, or `:eof` after receiving `close_notify`. That
callback must retain any partial record bytes when it returns `:would-block`.
A raw transport EOF signals `tls13-client-driver-error` with reason `:eof`.

`make-tls13-server-driver` accepts an optional `:quic-transport-parameters`
octet vector. When supplied, the driver copies the opaque value into extension
`#x0039` in `EncryptedExtensions`, where it is covered by the handshake
transcript. When the server is configured with this keyword, events returned
while processing a ClientHello containing extension `#x0039` include
`(:peer-quic-transport-parameters octets)` with its opaque value.
The event may be returned before the server verifies the client's Finished
message, so the value is provisional and unauthenticated. Consumers must defer
any decision that depends on its authenticity until the driver emits
`:handshake-complete`.

A configured server value requires that the ClientHello contain the extension;
otherwise the driver rejects the handshake with `missing_extension`. Omitting
the keyword means the driver does not require the ClientHello extension or add
it to `EncryptedExtensions`, preserving the existing TCP handshake behavior.
With the keyword omitted, a ClientHello that contains extension `#x0039` is
rejected with the fatal `unsupported_extension` alert.

The lower-level `make-tls-client` boundary requires a
`:verify-certificate` callback whenever a peer certificate is received. It
receives the certificate and must return non-`nil` to accept it; a missing
callback rejects the certificate. When that callback returns false or
signals a condition, the client reports `tls-client-verification-error`; its
`tls-client-verification-certificate` and `tls-client-verification-cause`
readers identify the certificate and cause. With this lower-level policy, a
caller-provided trust anchor is explicitly trusted and is not revalidated as
an issued certificate, so its CA constraint, key usage, and self-signature are
outside this policy. Certificates below the trust anchor remain subject to
chain, signature, validity, and usage checks; the anchor's validity interval
is still checked.

## QUIC TLS boundary

`make-quic-tls-boundary` handles TLS handshake bytes carried in QUIC CRYPTO
streams. Its contract levels are `:initial`, `:handshake`, and `:application`;
the former `:1-rtt` name remains accepted and is normalized to `:application`
for compatibility. `:0-rtt` is rejected because this boundary does not expose
0-RTT TLS secrets. The boundary tracks the TLS transcript and HelloRetryRequest
state. Its `on-crypto` callback receives `(boundary level bytes)` for emitted
handshake bytes. The TLS implementation supplies already-derived secrets
through `quic-tls-boundary-emit-secret`, once per direction; its `on-secret`
callback receives `(boundary level direction secret)`, with `direction` set to
`:read` or `:write`. After validating ServerHello and selecting ALPN, the TLS
handshake implementation calls `quic-tls-boundary-emit-cipher-suite` and
`quic-tls-boundary-emit-alpn`; those values are also available through
`quic-tls-boundary-cipher-suite` and `quic-tls-boundary-alpn`. The boundary
does not perform cipher-suite or ALPN negotiation.
Transport parameters are supplied as opaque RFC 9001 bytes and can be added to
ClientHello from a client boundary or EncryptedExtensions from a server
boundary. `quic-tls-boundary-send-message` emits handshake bytes directly as
CRYPTO data without TLS record framing. For contiguous, in-order CRYPTO bytes,
call `quic-tls-boundary-receive` without an offset; to provide an RFC 9001
CRYPTO frame with its offset and payload, call `quic-tls-boundary-feed-crypto`.
The exported `cl-tls-kit` package, also nicknamed `tls-kit`, is the package a
QUIC implementation such as `cl-quic-kit` can call.

This boundary does not implement QUIC packets or CRYPTO frame scheduling. It
does not provide a TLS provider, TCP transport, or end-to-end QUIC connection;
the QUIC implementation owns those layers and supplies CRYPTO offsets and
callbacks. QUIC transport parameters are a separate extension from SNI and
ALPN.

The project is MIT licensed.
