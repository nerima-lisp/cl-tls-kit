# cl-tls-kit

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

OCSP and CRL processing are intentionally out of scope.

Public API names and documentation are English. The project is MIT licensed.
