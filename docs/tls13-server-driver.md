# TLS 1.3 server handshake driver

The server driver implements a TLS 1.3 handshake state machine without owning a
socket or TLS record layer. It accepts one complete handshake message at a time
and returns wire messages and traffic secrets for a TCP adapter or QUIC
integration.

## Create a driver

`make-tls13-server-driver` accepts these keyword arguments:

| Argument | Meaning |
| --- | --- |
| `:provider` | A `tls13-crypto-provider` used for hashes, key derivation, and record-independent cryptographic operations. After loading cl-crypto-kit, create the standard provider with `(make-cl-crypto-kit-provider)`. |
| `:certificate-chain` | A nonempty list of DER certificates, leaf first. |
| `:private-key` | A matching cl-crypto-kit ECDSA P-256 or Ed25519 private key. |
| `:alpn-protocols` | Optional server preference order as strings. `nil` means no configured protocols. An offered list with no match produces `no_application_protocol`. |
| `:sni-callback` | Optional function called only for a full handshake. It receives the decoded hostname, or `nil` when the client omits SNI, and returns `(values der-chain private-key)`. If it returns no chain, the driver uses the default certificate and key. Return a chain and its matching key together to select another credential. PSK resumption skips credential selection and this callback. |
| `:ticket-key-store` | Optional store created by `make-tls13-server-ticket-key-store`. If omitted, the driver creates a private store. Pass one shared store to instances that should resume one another's tickets. The default maximum ticket lifetime is 86400 seconds; the accepted range is 1 to 604800 seconds. |
| `:supported-groups` | Supported TLS group IDs. Only X25519 (`#x001d`) and secp256r1 (`#x0017`) are accepted. The default preference order is X25519, then secp256r1. |
| `:cipher-suites` | Supported TLS 1.3 suite IDs. Only `#x1301` through `#x1304` are accepted; the default preference order uses that sequence. |
| `:clock` | Function returning Common Lisp universal time. Defaults to `get-universal-time`. |
| `:random` | Function accepting a byte count and returning that many random octets. The default uses cl-crypto-kit randomness. |

The constructor checks the DER chain, supported key type, and that the private
key matches the leaf certificate. For an SNI-selected chain, the driver checks
that its private key matches the selected leaf certificate.
When supplying `:random` outside tests, use a cryptographically secure source.
Tests may provide deterministic output through this hook.

## Consume handshake messages

The input to `tls13-server-driver-step` is the raw handshake message wire,
including its four-byte handshake header. Do not pass a TLS record. Use level
`:initial` for a ClientHello and `:handshake` for the client's Finished:

```lisp
(multiple-value-bind (driver events)
    (tls13-server-driver-step driver client-hello-wire :level :initial)
  (declare (ignore driver))
  events)
```

The driver updates its state in place and returns `(values driver events)`.
The returned event list contains plists with a `:type` key:

| Event | Fields |
| --- | --- |
| `:send` | `:level` and octet-vector `:wire`; `:content-type` is `:handshake` or `:alert`. |
| `:secret` | `:direction` (`:read` for client traffic, `:write` for server traffic), `:level` (`:handshake` or `:application`), and octet-vector `:secret`. |
| `:cipher-suite` | `:suite`, the negotiated suite ID. |
| `:alpn` | `:protocol`, the negotiated application protocol string. |
| `:ticket-issued` | `:identity`, an opaque encrypted ticket, and `:lifetime` in seconds. |
| `:handshake-complete` | `:resumed-p`, true when a PSK ticket resumed the connection. |
| `:alert` | `:description`, the TLS alert description. The matching `:send` event carries the alert bytes. |

Send events at `:initial` contain ServerHello or HelloRetryRequest. Encrypted
Extensions, Certificate, CertificateVerify, and Finished use `:handshake`.
NewSessionTicket and application traffic secrets use `:application`. The step
accepts ClientHello and client Finished in their expected states; other input,
including post-handshake messages at `:application`, produces an alert. The
`:send` event's `:wire` carries encoded handshake bytes, including the four-byte
header, or the two alert bytes; it never contains a TLS record. A TCP adapter
must frame outbound messages in records, decrypt inbound records, and install
keys from secret events. A QUIC adapter passes handshake bytes and traffic
secrets through its TLS integration without TLS record framing. Treat secret
event values as key material and do not write them to logs.

## Negotiation and resumption

When no ALPN extension is offered, the handshake proceeds without a selected
protocol.

If no offered key share matches a mutually supported group, the driver sends a
cookie-bearing HelloRetryRequest and validates the second ClientHello before
continuing. Known-invalid or doomed ClientHellos fail before CertificateVerify
signing. This includes malformed or duplicate extensions, no common group or
signature scheme, invalid key-share encoding, ALPN mismatch, invalid retry
state, an authenticated expired ticket, invalid ticket age, and a bad binder
for a recognized ticket. A ticket
with an unknown key ID or failed authentication is treated as an unknown PSK;
the driver continues with a full handshake when possible. A full handshake
uses an ECDSA P-256 or Ed25519 CertificateVerify signature. The driver does not
authenticate clients and rejects early data. Resumption accepts `psk_dhe_ke`
only, after validating the ticket lifetime, obfuscated age, ALPN and SNI
binding, cipher-suite hash, and binder.

## Rejected early data

The driver omits `early_data` from both EncryptedExtensions and NewSessionTicket.
Its tickets therefore grant no early-data allowance; their effective per-ticket
`max_early_data_size` is zero. The driver does not own TLS record parsing or
decryption, so the TCP listener must reject 0-RTT records before passing the
client's 1-RTT handshake messages to the driver.

When the initial ClientHello offers `early_data` and the server continues
without a HelloRetryRequest, the listener must try to decrypt incoming records
with the client handshake traffic key to find the start of the 1-RTT flight.
With the current zero per-ticket limit, the listener must close the connection
with a fatal `unexpected_message` alert if a record fails this trial
decryption. This immediate close is the listener's stricter local policy for a
ticket with no advertised early-data allowance, not a separate RFC requirement.
Because TLS permits zero-length Application Data, this policy may close even
when a rejected record would carry no Application Data bytes. A failed
decryption alone does not prove that a record contains early data, so the
listener must only use this handling while rejecting an explicit early-data
offer. Once a record decrypts successfully, the listener must pass it to
ordinary 1-RTT record and handshake processing.

If the server sends a HelloRetryRequest after an early-data offer, the listener
must treat an `application_data` record before the second ClientHello as
rejected early data. The second ClientHello must not contain `early_data`. With
the current zero per-ticket limit, close the connection if such a record
arrives, using the same stricter local fatal `unexpected_message` policy. For a
future positive limit, skip these records within the budgets below.

If a future driver advertises a positive `max_early_data_size` but rejects an
early-data offer, the listener must follow RFC 8446's bounded skip behavior.
Without early-data keys, it cannot count the RFC's limit exactly: that limit
counts plaintext Application Data bytes, excluding padding and the inner
content type. Use a conservative wire-byte counter instead, counting each
discarded record's full size (the five-byte header plus the full TLSCiphertext
fragment, including AEAD expansion). Do not let this counter exceed the
ticket's `max_early_data_size` or a finite per-connection local byte cap. Also
enforce a finite per-connection record-count limit. Before buffering, enforce
`TLSCiphertext.length <= 2^14 + 256` bytes. This field excludes the five-byte
record header. A larger `TLSCiphertext.length` must terminate the connection
with a fatal `record_overflow` alert before buffering or trial decryption, on
all paths including early-data rejection. Before discarding a failed record or
skipping an HRR-path record, check both remaining budgets. If either would be
exceeded, terminate with a fatal `unexpected_message` alert and stop draining.
RFC 8446 §4.6.1 recommends this alert when the plaintext Application Data
limit is exceeded. This contract also applies the same alert when the stricter
wire-byte or record-count budget is exceeded; record overhead can therefore
cause closure before the plaintext limit is reached. Outside the explicit
rejection paths, use normal TLS record error handling; in particular, a
decryption failure for accepted early data is fatal with `bad_record_mac` as
required by [RFC 8446 §5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2).

This contract follows [RFC 8446 §4.2.10](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10), which specifies trial decryption or skipping encrypted records when the server rejects early data, and [§4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1), which recommends terminating with `unexpected_message` when the configured early-data limit is exceeded.

```lisp
(defparameter *ticket-store*
  (make-tls13-server-ticket-key-store :ticket-lifetime 86400))

(rotate-tls13-server-ticket-key-store *ticket-store*)
```

The store creates an initial AES-256-GCM key. Rotation is explicit and is not
scheduled by the driver; it installs a new key and retains prior decrypt keys
for the configured ticket lifetime, up to seven days. The store keeps keys in
memory, so replacing it after a restart invalidates tickets encrypted by its
previous keys. It does not expose ticket keys or resumption PSKs through events.

## Listener resource limits

CertificateVerify signing is expensive. The reported aarch64 measurements were
about 215 ms for ECDSA P-256 and 265 ms for Ed25519 per signature; machine model
and workload details were not recorded, so these are not capacity guarantees.
A valid unauthenticated ClientHello can cause roughly 0.2 seconds of server CPU
use when it reaches a full handshake. `cl-http-kit`'s HTTPS listener must apply
FR-016's configurable maximum total concurrent connection and concurrent
handshake limits, rejecting connections that exceed either cap. The driver
does not choose numeric cap values. FR-016 does not define a handshake-rate
limit. The listener should separately limit handshake frequency to reduce CPU
exhaustion from repeated handshakes.

