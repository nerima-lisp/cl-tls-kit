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
| `:ticket-key-store` | Optional store created by `make-tls13-server-ticket-key-store`. When session tickets are enabled, omitting this option makes the driver create a private store. Pass one shared store to instances that should resume one another's tickets. The default maximum ticket lifetime is 86400 seconds; the accepted range is 1 to 604800 seconds. |
| `:session-tickets` | Whether to issue NewSessionTicket messages and accept PSK resumption. Defaults to `t`. With `nil`, the driver creates no internal ticket-key store, parses an offered PSK extension, checks that `psk_dhe_ke` was offered, then declines resumption without opening the ticket or verifying its binder. It continues with a full handshake. |
| `:quic-transport-parameters` | Optional octet vector containing opaque QUIC transport-parameter bytes. When supplied, the driver copies the value into extension `#x0039` in `EncryptedExtensions`. The full encoded extensions vector, including its other extensions and their headers, must fit TLS's 16-bit length. |
| `:supported-groups` | Supported TLS group IDs. Only X25519 (`#x001d`) and secp256r1 (`#x0017`) are accepted. The default preference order is X25519, then secp256r1. |
| `:cipher-suites` | Supported TLS 1.3 suite IDs. Only `#x1301` through `#x1304` are accepted; the default preference order uses that sequence. |
| `:clock` | Function returning Common Lisp universal time. Defaults to `get-universal-time`. |
| `:random` | Function accepting a byte count and returning that many random octets. The default uses cl-crypto-kit randomness. |
| `:max-consecutive-key-updates` | Nonnegative integer limit for accepted KeyUpdate messages since the last successfully decrypted record with `TLSInnerPlaintext.content_type` equal to `application_data`. Defaults to `32`; `0` rejects the first KeyUpdate. |

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
Most entries in the returned event list are plists with a `:type` key:

| Event | Fields |
| --- | --- |
| `:send` | `:level` and octet-vector `:wire`; `:content-type` is `:handshake` or `:alert`. |
| `:secret` | `:direction` (`:read` for client traffic, `:write` for server traffic), `:level` (`:handshake` or `:application`), and octet-vector `:secret`. |
| `:cipher-suite` | `:suite`, the negotiated suite ID. |
| `:alpn` | `:protocol`, the negotiated application protocol string. |
| `:ticket-issued` | `:identity`, an opaque encrypted ticket, and `:lifetime` in seconds. Emitted only when `:session-tickets` is enabled. |
| `:handshake-complete` | `:resumed-p`, true when a PSK ticket resumed the connection. |
| `:alert` | `:description`, the TLS alert description. The matching `:send` event carries the alert bytes. |

With `:quic-transport-parameters` configured, events returned while
processing a ClientHello containing extension `#x0039` include
`(:peer-quic-transport-parameters octets)`. The octets are an opaque copy of
the extension data. The event is returned before the server verifies the
client's Finished message, so the octets are provisional and unauthenticated.
A consumer may parse or buffer them, but must defer any decision that depends
on their authenticity until the driver emits `:handshake-complete`, after it
verifies Finished. The event is returned for the first ClientHello that
produces HelloRetryRequest and for the accepted second ClientHello.

With `:quic-transport-parameters` configured, the driver rejects a ClientHello
without extension `#x0039` with a fatal `missing_extension` alert. Without the
keyword, it neither requires extension `#x0039` in ClientHello nor adds it to
`EncryptedExtensions`, retaining its existing TCP behavior. In this mode, a
ClientHello that contains extension `#x0039` is rejected with a fatal
`unsupported_extension` alert.

Send events at `:initial` contain ServerHello or HelloRetryRequest. Encrypted
Extensions, Certificate, CertificateVerify, and Finished use `:handshake`.
NewSessionTicket and application traffic secrets use `:application`. The step
accepts ClientHello and client Finished in their expected states. At
`:application`, it accepts KeyUpdate messages subject to the configured limit;
other post-handshake messages produce an alert. The `:send` event's `:wire`
carries encoded handshake bytes, including the four-byte header, or the two
alert bytes; it never contains a TLS record. A TCP adapter must frame outbound
messages in records, decrypt inbound records, and install keys from secret
events. A QUIC adapter passes handshake bytes and traffic secrets through its
TLS integration without TLS record framing. Treat secret event values as key
material and do not write them to logs.

## Terminate a connection

The driver does not read TLS records. Call
`(tls13-server-driver-close driver)` when the record or transport layer reports
a read failure, receives a peer alert, or ends the connection normally. Close
clears per-connection secret buffers and callback references, releases the
driver's ticket-store reference, and marks the driver failed. If the driver
created the store, close also destroys it and wipes its keys. A store passed by
the caller remains usable. Fatal-alert cleanup also destroys an internally
created store. Close emits no alert, and later calls to
`tls13-server-driver-step` return no events.

## Limit KeyUpdate messages

If another KeyUpdate would exceed `:max-consecutive-key-updates`, the driver
returns a fatal `unexpected_message` alert before deriving keys for that
update. Pass KeyUpdate handshake messages to `tls13-server-driver-step` with
`:level :application`.

The driver does not decrypt records. After successfully decrypting an inbound
record, the connection adapter must call
`(tls13-server-driver-note-application-data-received driver)` only when the
inner `TLSInnerPlaintext.content_type` is `application_data`. Call it for every
such record, including one with an empty fragment. Do not call it for an
encrypted record whose inner content type is `handshake`, such as one carrying
KeyUpdate.

## Negotiation and resumption

When no ALPN extension is offered, the handshake proceeds without a selected
protocol.

If no offered key share matches a mutually supported group, the driver sends a
cookie-bearing HelloRetryRequest and validates the second ClientHello before
continuing. Malformed or invalid ClientHellos fail before CertificateVerify
signing. This includes duplicate extensions, no common group or
signature scheme, invalid key-share encoding, ALPN mismatch, invalid retry
state, an authenticated expired ticket, invalid ticket age, and a bad binder
for a recognized ticket. A ticket with an unknown key ID or an invalid AEAD tag
is treated as an unknown PSK;
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
cause closure before the plaintext limit is reached. The current driver rejects
early data. If a future version accepts it, a decryption failure outside the
explicit rejection paths must follow normal TLS record error handling and use
fatal `bad_record_mac`, as required by
[RFC 8446 §5.2](https://www.rfc-editor.org/rfc/rfc8446#section-5.2).

This contract follows [RFC 8446 §4.2.10](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.10), which specifies trial decryption or skipping encrypted records when the server rejects early data, and [§4.6.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.6.1), which recommends terminating with `unexpected_message` when the configured early-data limit is exceeded.

## Ticket-key store

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
The application owns any store passed with `:ticket-key-store`, including
stores shared by multiple drivers. Call
`(destroy-tls13-server-ticket-key-store store)` when the server stops to zero
its current and previous keys and make the store unusable. Closing a driver
releases its reference to a caller-owned store but leaves the store usable.

## Listener resource limits

A full handshake requires CertificateVerify signing, which consumes CPU. The
listener must set finite limits for total connections and concurrent
handshakes, and separately limit handshake frequency. The driver does not
choose the limit values.
