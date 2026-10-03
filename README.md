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

OCSP and CRL processing are intentionally out of scope. Certificate parsing
and chain checks do not fetch or evaluate revocation status, and there are no
OCSP or CRL APIs.

## TLS 1.3 negotiation

The exported cipher-suite constants and helpers cover these RFC 8446 suites:

- `TLS_AES_128_GCM_SHA256` (`0x1301`)
- `TLS_AES_256_GCM_SHA384` (`0x1302`)
- `TLS_CHACHA20_POLY1305_SHA256` (`0x1303`)
- `TLS_AES_128_CCM_SHA256` (`0x1304`)
- `TLS_AES_128_CCM_8_SHA256` (`0x1305`)

The implementation passes supported-group IDs through ClientHello and key
share helpers. The built-in client defaults are X25519 (`0x001d`) in
`tls-client-make-client-hello` and X25519 plus secp256r1 (`0x0017`) in the
standalone handshake driver. A crypto/provider integration must supply the
actual key generation and shared-secret operations.

SNI and ALPN are optional ClientHello extensions. `make-tls-client` accepts
`hostname` and `alpn-offered`; `tls-client-make-client-hello` encodes them
with `encode-sni-extension` and `encode-alpn-extension`. The driver accepts
`hostname` and `alpn` and includes the same extensions. The negotiated ALPN
value is available through `tls-client-alpn` after provider input is applied.

## Client and stream boundaries

`make-tls-client` is a boundary around callbacks, not an independent
provider-neutral handshake implementation. A provider is a function or a
property list of callbacks such as `:client-hello`, `:handshake`,
`:key-update`, and `:close-notify`; the client invokes these with the client
and callback-specific input. `transport-read` returns one encoded TLS record
or `nil`, and `transport-write` receives the client and encoded bytes.
`tls-client-read` and `tls-client-write` operate only after the client is
connected. `make-tls-client-over-tcp` supplies a blocking SBCL TCP stream
adapter; other implementations must provide transport callbacks directly.

`make-tls13-client-driver` is the more prescriptive callback-driven TLS 1.3
handshake sequence. It requires a `tls13-crypto-provider`, a key-exchange
plist containing `:generate` and `:shared-secret`, and sends encoded
handshake messages to its `on-send` callback. It sequences ClientHello,
HelloRetryRequest, ServerHello, EncryptedExtensions, Certificate,
CertificateVerify, and Finished. When `trust-anchors` is supplied, it parses
the peer certificate chain, applies the hostname and chain policy, and verifies
CertificateVerify through the provider. Supply `transport-read` and
`transport-write` callbacks, or use `make-tls13-client-driver-over-tcp`, to
read and write TLS records. `tls13-client-driver-connect`, `-write`, `-close`,
and `-key-update` provide the blocking stream lifecycle; cryptographic key
exchange and certificate-signature verification remain provider callbacks.

The lower-level `make-tls-client` boundary requires a
`:verify-certificate` callback whenever a peer certificate is received; a
missing callback rejects the certificate. A caller-provided trust anchor is
explicitly trusted and is not revalidated as an issued certificate, so its
CA constraint, key usage, and self-signature are outside this policy. All
certificates below the trust anchor remain subject to chain, signature,
validity, and usage checks.

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

The project supports TLS 1.3 only. It does not negotiate TLS 1.2 or fall back
to it. OCSP and CRL fetching or revocation-status evaluation are outside the
scope of certificate parsing and chain verification.

## Public API

The `cl-tls-kit` package, also available as `tls-kit`, exports the DER, PEM,
`cl-tls-kit.x509`, certificate verification, TLS 1.3 record/handshake/key
schedule, callback client, handshake driver, and QUIC boundary APIs described
above. Public API names and documentation are English. The project is MIT
licensed.
