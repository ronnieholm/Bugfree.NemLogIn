# Introduction to asymmetric cryptography and NemLog-in

## Overview

- Main problem solved by using cryptography for encryption/signing
  - Facilitates bidirectional exchange of messages (XML documents) over an
    unsecure medium (the Internet) and through unsecure intermediaries (web
    browsers).

- Main problem solved by using SAML
  - XML dialect for request/response exchange of messages with a central service
    (identity provider). The identity provider owns its user database such that
    applications (service providers) don't have to.

- Other well-known identity providers
  - Office 365, Facebook, Google
  - Kerberos authentication (part of Windows Active Directory)
    - Try klist Windows command

- Cryptographic system using pairs of keys
  - Public key to be distributed freely
  - Private key known only to owner

- [Key generation](https://upload.wikimedia.org/wikipedia/commons/3/32/Public-key-crypto-1.svg)
- [Encryption and decryption](https://upload.wikimedia.org/wikipedia/commons/f/f9/Public_key_encryption.svg)
  - Only the holder of the paired private key can decrypt a message encrypted
    with the public key.
- [Signing and validation](https://upload.wikimedia.org/wikipedia/commons/2/2b/Digital_Signature_diagram.svg)
  - Public key is used to verify that a holder of the paired private key sent
    the message.
  - Combine a message with a computation using the private key to create a short
    digital signature of the message.
  - Message is signed with the sender's private key and can be verified by
    anyone who has access to the sender's public key. Otherwise, message
    could've come from anyone with access to the public key.

## Request / response SAML example

- Example request
  - By breakpointing in ```dk.nita.saml20.protocol.Saml20SignonHandler.TransferClient(...)```
  - The request argument holds the XML below and the method hashes its content
    and also writes the XML below to the log file.
  
  ```xml
  <?xml version="1.0"?>
  <q1:AuthnRequest ID="idea1e6977f4b541e0b52a04ae1d8a95b9" 
                   Version="2.0"
                   IssueInstant="2017-10-27T06:55:09.0009Z"
                   Destination="https://login.test-nemlog-in.dk/adfs/ls/" 
                   ForceAuthn="false" 
                   IsPassive="false" 
                   xmlns:q1="urn:oasis:names:tc:SAML:2.0:protocol">
    <Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://saml.oiosaml-net.dk</Issuer>
      <Conditions xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
        <AudienceRestriction>
          <Audience>https://saml.oiosaml-net.dk</Audience>
        </AudienceRestriction>
      </Conditions>
    </Issuer>
  </q1:AuthnRequest>
  ```

- Example response (part of larger XML document)
  - By breakpointing in ```dk.nita.saml20.protocol.Saml20SignonHandler.HandleAssertion(...)```
  - The elem argument's Outer property holds the XML below and also writes the XML 
    below to the log file.

  ```xml
  <AttributeStatement xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Attribute Name="urn:oid:2.5.4.3" 
               NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <AttributeValue>Tille Jepsen</AttributeValue>
    </Attribute>
    <Attribute Name="urn:oid:0.9.2342.19200300.100.1.1" 
               NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
      <AttributeValue>PID:9208-2002-2-884449999417</AttributeValue>
    </Attribute>
  </AttributeStatement>
  ```
## Required keys / certificates

- ```
  Sender                Receiver
  K_sender_enc_pub      K_receiver_enc_pub            
  K_sender_enc_pri      K_receiver_enc_pri
  
  K_sender_sig_pub      K_receiver_sig_pub
  K_sender_sig_pri      K_receiver_sig_pri
  ```

- There's no technical difference between enc and sig certificates -- it's about
  designation of usage. In principle, certificates may be switched or the same
  certificate may be used for both encryption and signing.

  Pub/pri pair is grouped in a certificate (file, container). Certificate is 
  oftentimes password protected if it contains a private key.

  Certificate may itself be signed with another certificate to construct a chain
  of trust up to a root authority, possibly with intermediaries.
  
- Above encrypting/signing happens within the TCP/IP application layer.

- [Transport/session layer encryption](http://bpastudio.csudh.edu/fac/lpress/471/hout/netech/tcpvosi2.gif)
  of communication takes place also.
  
- ```
  Server              Client  
  K_server_tls_pub    K_client_tls_pub
  K_server_tls_pri    K_client_tls_pri
  ```

- Client usually don't have its own certificate so it cannot prove its identity
  to the server.

- With TLS, payload isn't actually encrypted/decrypted using asymmetric
  cryptography. Only the initial exchange of the session key is. During initial
  TLS setup, Diffie-Hellman key exchange is often used to generate and exchange
  a symmetric key used to encrypt/decrypt remaining traffic (because symmetric
  encryption provides better performance).

## Algorithm for A -> B transmission 

From A -> B

On A:
0. Assume XML document constructed by application (valid SAML request or response)
1. Compute SHA256 hash of (0)
2. Encrypt (1) using K_A_sig_pri
3. Append (0) to (2)
4. Encrypt (3) with K_B_enc_pub
5. Transmit (4) using query string (or HTTP form POST)

On B:
0. Assume received encrypted cipher text
1. Decrypt (0) using K_B_enc_pri
2. Compute SHA256 of (0) excluding the signature part of XML
3. Decrypt signature using K_A_sig_pub
4. Compare (2) with (3)
5. Application-level processing of XML document

Any one with access to the public key could've sent the massage. By verifying
the signature, we know that the message was sent by someone who holds A's
private key which, hopefully, is A only.

Each message includes both a unique ID and a timestamp, making replay attacks
hard as a single character change to the clear text message would produce a
vastly different SHA256 hash value. And because the SHA256 hash is a one-way
function it cannot be reversed.

Example: suppose roundToTen is our hash function. Then a number
of inputs would yield the same hash value.

``` text
Input = 5 gives output = 10
Input = 4 gives output = 10
Input = 3 gives output = 10
...
```

Given these hash values, we can't figure out what the original values were.
Multiple values can lead to the same hash. Yet, verifying the hash of some input
is a fast operation.

## Certificate Revocation List

- Three-way TCP handshake required to connect to Nets' CRL server
- Connection tracking table of network equipment at service provider often
  prevents connections originating from inside the network
- Four tuple of (Src IP, Src port, Dst IP, Dst port) per connection doesn't
  exist in connection tracking table, making outbound connection impossible
- CRL server checking can be disabled

## How public keys are distributed and located by parties

- [IdP metadata](../src/Bugfree.NemLogIn.Web/IdP-metadata)
  - K_IdP_enc_pub
  - K_IdP_sig_pub 

- [SP metadata](https://github.com/digst/OIOSAML.Net/blob/master/src/dk.nita.saml20/IdentityProviderDemo/idp-metadata/spmetadata/795b9ec9f6cc135831927187ad34f318)
  - K_SP_enc_pub
  - K_SP_sig_pub

Example: extract base 64 encoded part of metadata and save as .cer file to open
certificate using associated file handler, certutil command, or OpenSSL package.

Metadata isn't secret. It's public keys + service description. Metadata is
downloaded by calling into the metadata.ashx handler, part of oiosaml.net.

Strictly speaking, metadata.ashx endpoint isn't required for a service to
operate, but useful for debugging. Other services in production tends to expose
the endpoint.

Private keys are stored in the Windows certificate store on SP's machine and
must be made accessible to the IIS app pool user. Otherwise that account cannot
access the private key and SP throws an exception.

HTTPS = SSL = TLS certificates are stored in certificate store as well.

## Overview of oiosaml.net package and MVC sample

- [.NET SAML2 Service Provider Framework](https://github.com/digst/OIOSAML.Net)
- [Introduction to SAML - Chalktalk on what is it, how it is used](https://www.youtube.com/watch?v=S9BpeOmuEz4)
- [Wikipedia: SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0)