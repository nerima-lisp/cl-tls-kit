# Changelog

## 0.4.1

### Security

- Verify TLS peer certificates and enforce TLS 1.3 handshake message ordering.
- Close transports on fatal peer alerts and read failures, and clear secrets on those paths.
- Zero temporary DHE values and resumption secrets after use or ticket issuance failures.
- Compare X.509 distinguished names by RDN and AVA structure using the rules in RFC 5280 §7.1 and RFC 4518.
- Reject ambiguous numeric IPv4 hostnames before DNS subject alternative name matching.
- Zero expired TLS 1.3 server ticket keys and add `destroy-tls13-server-ticket-key-store` to zero all keys and invalidate the store.
- Reject partial TLS record headers and oversized records before allocating their payloads.
- Apply the encoded RSA-PSS parameters when verifying certificate signatures.
