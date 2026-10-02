# cl-tls-kit

Common Lisp building blocks for TLS 1.3 and X.509 tooling. The implementation
currently targets TLS 1.3 (RFC 8446), including the record layer, handshake
messages, key schedule, a callback-based client boundary, and QUIC TLS
boundaries. It does not implement a TLS 1.2 protocol stack; the client only
checks TLS 1.2/1.1 downgrade sentinels in a TLS 1.3 ServerHello.

Strict Distinguished Encoding Rules (DER) and Privacy-Enhanced Mail (PEM)
building blocks for Common Lisp TLS and X.509 tooling.

The ASN.1 layer rejects indefinite lengths, non-minimal length encodings,
non-minimal tags and INTEGER encodings, truncated values, and invalid BIT
STRING padding. `der-decode` accepts exactly one complete DER object.

The PEM layer supports labeled blocks and standard Base64 with whitespace. It
does not implement encrypted PEM. X.509 parsing is available in
`cl-tls-kit.x509`; chain verification, trust-store selection, and SAN hostname
matching are available from `cl-tls-kit`. Signature verification is delegated
to the `cl-crypto-kit` API when that kit is present.

OCSP and CRL processing are intentionally out of scope. Certificate parsing
and chain checks do not fetch or evaluate revocation status, and the library
does not expose OCSP or CRL APIs.

## Public API

The `cl-tls-kit` package (also available as `tls-kit`) exports these API
families:

- `der-*` and `encode/decode-der` for strict, single-object DER parsing and
  encoding.
- `pem-*` and `encode/decode-pem` for unencrypted PEM blocks.
- `x509-*` in `cl-tls-kit.x509` for X.509 certificate parsing and extracted
  fields.
- `verify-certificate`, `verify-certificate-chain`, `load-trust-store`, and
  hostname matching for certificate policy checks.
- `tls13-*` for TLS 1.3 key schedule, handshake messages, verification, and
  state transitions.
- `tls-client-*` and `make-tls-client-over-tcp` for the callback-based TLS 1.3
  client boundary. The current release does not claim a provider-independent
  full handshake driver; handshake, record, and key-schedule operations are
  supplied through the provider callbacks.
- TLS record and QUIC boundary constructors, encoders, decoders, and crypto
  callback interfaces.

Cryptographic signing, verification, hashing, and AEAD operations are
delegated to the provider interface. `cl-crypto-kit` is an optional weak
dependency for the provider-backed checks and RFC 8448 vector test.

Public API names and documentation are English. The project is MIT licensed.
