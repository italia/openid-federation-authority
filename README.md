# OpenID Federation Authority

## Technical requirements
OpenID Federation Authority is a backend project developed in Java with Spring Boot Framework that include the functionality of Federation Authority implementing the Infrastructure of Trust according to [Italian EUDI Wallet Technical Specifications](https://italia.github.io/eudi-wallet-it-docs/v0.7.0/en/trust.html) and following the [OpenID Federation 1.0 specs](https://openid.net/specs/openid-federation-1_0.html).

## API
### GET .well-known/openid-federation
Metadata that an Entity publishes about itself, verifiable with a trusted third party (Superior Entity). It's called Entity Configuration.

### GET /list
Lists the Subordinates.

### GET /fetch?sub=...&iss=...
Returns a signed document (JWS) about a specific subject, its Subordinate. It's called Entity Statement.

### POST /status?sub=...&trust_mark_id=...
Returns the status of the issuance (validity) of a Trust Mark related to a specific subject.

### POST /resolve?sub=...&type=...&anchor=...
Fetch resolved metadata and Trust Marks for an Entity. The resolver fetches the subject's Entity Configuration, assembles a Trust Chain that starts with the subject's Entity Configuration and ends with the specified Trust Anchor's Entity Configuration, verifies the Trust Chain, and then applies all the policies present in the Trust Chain to the subject's metadata.

### GET /historical-jwks
Lists the expired and revoked keys, with the motivation of the revocation.

### POST /onboard
Request to onboard a subordinate.


# License: 
Apache License Version 2.0

