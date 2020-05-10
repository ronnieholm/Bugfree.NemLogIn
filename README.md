# Bugfree.NemLogIn

This repository contains

- An ASP.NET MVC demo service provider (SP) adapted from the regular ASP.NET
  [WebSiteDemo](https://github.com/digst/OIOSAML.Net/tree/master/src/dk.nita.saml20/WebsiteDemo)
  SP part of the [OIOSAML.Net](https://github.com/digst/OIOSAML.Net)
  authentication solution.
- [Notes on asymmetric cryptography and
  NemLog-in](docs/Introduction-to-asymmetric-cryptography-and-NemLog-in.md) to
  augment official NemLog-in documentation which assumes the reader is already
  familiar with the concepts of certificates, encryption, and signing.

## Getting started

After launching the ASP.NET MVC demo SP and navigating to
https://oiosaml-net.dk:20002/Home, it looks like this:

![Home](docs/Home.png)

Following the "Goto page requirering authentication" link causes the OIOSAML.Net
library to take over. It redirects the user's browser to a NemLog-in identity
provider (IdP), or in case of multiple providers presents the user with a list
of IdPs to choose from.

On successful authentication with an IdP, the user's browser is redirected back
to https://oiosaml-net.dk:20002/RequiresAuthentication, the page originally
requirering authentication, listing each SAML assertion returned by the IdP:

![Requires authentication](docs/RequiresAuthentication.png)

In order to run the MVC demo, one must have carried out the [.NET SAML2 Service
Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx)
setup. To validate prerequisites, ensure the OIOSAML.Net provided local demo and
the remote NemLog-in test IdPs are working with the OIOSAML.Net demo SP.

The following are supplementary notes on how to setup the .NET SAML2 Service
Provider framework.

## Setting up a new service provider

These steps have been verified on Windows Server 2019. 

First, the steps outlined in OIOSAML.Net
[readme.md](https://github.com/digst/OIOSAML.Net/blob/master/readme.md) was
carried out as-is.

### Cloning OIOSAML.Net source from Github

For easier debugging and the ability to step through OIOSAML.Net library code,
source distribution is preferred over referencing the
[NuGet](https://www.nuget.org/packages/dk.nita.saml20) package.

To clone and view available releases (current development takes place in
master):

    % git clone https://github.com/digst/OIOSAML.Net.git
    % git tag
    2.0.0
    ...
    release-2.0.2
    release-2.0.3

In general, one should make a note of the commit hash used. That way it's easier
to review changes during an upgrade.

### Copying projects from OIOSAML.Net into Bugfree.NemLogIn.Web

To make use of NemLog-in from source, we must

   1. Copy the dk.nita.saml20 and dk.nita.saml20.ext.audit.log4net projects from
      the Git repository into our solution (or use Git submodules). If the
      project directories already exist, first remove those or use a directory
      diffing tool. Simply overriding the folder structures will not remove any
      files no longer part of OIOSAML.Net.

   2. The dk.nita.saml20 and dk.nita.saml20.ext.audit.log4net projects cannot
      compile outside the OIOSAML.Net solution unless we append the content of
      [src\dk.nita.saml20\CommonAssemblyInfo.cs](https://github.com/digst/OIOSAML.Net/blob/master/src/dk.nita.saml20/CommonAssemblyInfo.cs)
      to the projects' AssemblyInfo.cs files. 
      
      Rather than maintain version attributes in two places, OIOSAML.Net has
      opted for a common location which after copying the projects would lead to
      the following compiler error:

      ```
      error CS2001: Source file 'Bugfree.NemLogIn\src\dk.nita.saml20\..\CommonAssemblyInfo.cs' could not be found.
      ```

      After appending the lines below to the existing AssemblyInfo.cs files

      ```
      // Copied from CommonAssemblyInfo.cs
      [assembly: AssemblyVersion("2.0.2.0")]
      [assembly: AssemblyFileVersion("2.0.2.0")]
      [assembly: AssemblyInformationalVersion("2.0.2.0")]
      ```

      delete from the projects the file reference to CommonAssemblyInfo.cs to
      resolve the compilation error.

   3. Finally, add to Bugfree.NemLogIn.Web references to the dk.nita.saml20 and
      dk.nita.saml20.ext.audit.log4net projects. Use of Log4Net is hardcoded
      into the solution.

### Setting up Bugfree.NemLogIn.Web to use OIOSAML.Net

The following supplements [.NET SAML2 Service Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx),
Section 6.1. A one-time key card is required to login against the NemLog-in test
environment, but not the Demo IdP:

  1. Copy IdP-metadata files from
     OIOSAML.Net\src\dk.nita.saml20\WebsiteDemo\idp-metadata into
     \src\Bugfree.NemLogIn.Web\IdP-metadata. This enables the SP to communicate
     with the local demo and remote IdPs.

  2. To test against the NemLog-in test IdP, the IP at which the SP is running
     must be whitelisted with Nets' certificate revocation list
     server. Otherwise, login against the IdP will succeed but once the result
     is posted back to the SP, the certificate used to sign the IdP's response
     cannot be verified, causing an exception at the SP. Testing from a
     non-whitelisted IP, we can disable verifying certification chain trust by
     editing Web.config, adding the omitAssertionSignatureCheck attribute:

     ```
     <IDPEndPoints metadata="IdP-metadata">
         <add id="https://saml.test-nemlog-in.dk/" omitAssertionSignatureCheck="true" />
     </IDPEndPoints>
     ```
	 
  3. The SP must be accessible at https://oiosaml-net.dk:20002 for the login
     process to succeed. The reason for this is that the SP is using the
     OIOSAML.Net demo SP's metadata, of which the URL is part, and its
     certificates.
     
     For some reason, even though oiosaml-net.dk is mapped to 127.0.0.1 in the
     hosts file, IISExpress sometimes may fail to respond to requests to
     oiosaml-net.dk. Opening this URL in a browser may result in an error
     message in the browser:

     ```
     Bad Request - Invalid Hostname
     HTTP Error 400. The request hostname is invalid.
     ```

     With Visual Studio 2019, the IISExpress config file is dynamically
     generated each time a project is loaded. It's stored in
     src\.vs\config\applicationhost.config. To make IISExpress respond to
     requests for oiosaml-net.dk, open this file and look for the line below:

     ```
     <binding protocol="https" bindingInformation="*:20002:localhost" />
     ```

     Then substitute the line with
 
     ```
     <binding protocol="https" bindingInformation="*:20002:*" />
     ```

   Now IISExpress responds to any domain on port 20002, not just
   https://localhost:20002.

### Updating the metadata file for a new service provider

To make setup easy, Bugfree.NemLogIn shares its metadata with the OIOSAML.Net
demo SP. If we were to create a new SP, hosted at a different URL and using
different certificates for encryption and signing, the SP's metadata must be
updated.

Metadata is updated by direct changes to an XML file. Metadata resides in the
file system, and is also available through a SP's metadata.ashx endpoint. Some
SPs remove the metadata.ashx in production, but nothing about the metadata is
secret. After modifying the metadata, the file must be uploaded through the
(NemLog-in administration portal)[https://administration.nemlog-in.dk]. Everyone
with an employee NemID may be granted access by a company administrator to
upload new metadata.

Starting from the demo SP's metadata, here're the parts that require
substitution to work with a new SP:

  1. Inside the EntityDescriptor element, update the entityID attribute to match
     the new environment. While the string resembles a URL, it doesn't have to
     be a valid URL -- it's a URI not a URL. The convention is to prepend "saml"
     and the type of environment to the SP's URI. For a test environment, the
     URI would be https://saml.test.myservice.dk and for production it would be
     https://saml.myservice.dk.

  2. Update the two SingleLogoutService elements by changing the Location and
     ResponseLocation attributes to match the base URL of the SP. Then append
     logout.ashx, e.g., https://myservice/logout.ashx.

  3. Update the AssertionConsumerService element's Location attribute to match
     the base URL of the SP. Then append login.ashx, e.g.,
     https://myservice/login.ashx.

  4. Inside the two X509Certificate elements, paste in the public key of the
     SP's certificate. In principle, separate public keys may be used for
     encryption and signing, but in practice using the same key seems common
     practice.

  5. Update the ContactPerson child elements with relevant information for the
     SP.

### Updating the Web.config file for a new service provider

The Web.config file contains a few environment specific settings that must match
the SP's metadata:

  1. The SigningCertificate element's findValue attribute must be updated to the
     thumbprint of the SP's certificate. The private key installed in the
     certificate store is what's used for signing.

  2. The inner text of the Audience element must match what's in the SP's
     metadata, i.e., the entityId value. This value is sent to the IdP and is
     how the IdP identifies the SP calling it. SAML assertions are issued to and
     valid for this audience only.

## Develop locally by using the OIOSAML.Net local IdP

During SP development, continuously having to login to the NemLog-in test IdP is
a hassle. For this case use the local IdP. This way, any assertion returned by a
full-featured NemLog-in IdP, and relevant to the SP's domain, can be easily
modified, possibly exercising different code paths useful in testing.

## Troubleshooting

### Browser shows "Saml20Indentity not initialized" error message

The application has lost track that the user is logged in. If we logout by
navigating to https://oiosaml-net.dk:20002/logout.ashx and navigate back to a
page requirering authentication, the OIOSAML.Net library will redirect the
browser to the NemLog-in IdP which may determines that the user is still logged
into it. The IdP then redirects the browser back to the original page, providing
the SP the SAML response once again, but without the need for the user to
explicitly login. It's unclear if this error message is a feature or a bug.

## Debugging outside of Visual Studio

On a production server with no Visual Studio installed, besides enabling SP
log4net logging, zero footprint tools such as
[dnspy](https://github.com/0xd4d/dnSpy) or
[WinDbg](https://developer.microsoft.com/en-us/windows/hardware/download-windbg)
are useful for tracing code. dnspy may disassemble IL to C# and supports setting
breakpoints and inspecting the value of variables based on reverse engineered
C#. WinDbg is more low-level and solely operates on IL and lower levels. With
these tools, execution may be traced through the SP's code as well as that of
the OIOSAML.Net component without source on a server.

Setting breakpoints inside the OIOSAML.Net component enables access to the raw
XML request and response and to follow request and response flows from inside
the library. In error cases, seeing where processing fails may be useful in
resolving the issue.

Running a man in the middle proxy such as Fiddler on client and server is
sometimes valuable to see what actually goes over the wire. Fiddler supports
decrypting TLS traffic through a self-signed root certificate. However, even
decrypting TLS traffic, SAML requests and responses remain encrypted. They're
best decrypted by way of the breakpoint technique mentioned above.

SAML authentication happens through a number of browser redirection
requests. The SP and IdP provider don't communicate directly. Instead each ask
the browser to redirect somewhere else during the request and response part of
authentication. Therefore the browser's F12 development tools aren't useful is
tracing requests and responses. Every time a redirect takes place, the network
request tab resets.

To supplement or replace a Fiddler, Wireshark may be used. As communication
takes place over TLS, traffic must be decrypted. Unlike Fiddler, which acts as a
man in the-middle proxy, Wireshark records the traffic as is, invisible to
communicating parties. Wireshark may be the better tool for correlating traffic
on multiple protocol or if/when and IdP employs certificate pinning.

In order for Wireshark to decrypt TLS sessions, a browser's shared sessions keys
must be available to Wireshark. Chrome and Firefox, but not Edge, supports
[dumping shared session
keys](https://www.steffr.ch/inspect-ssl-tls-traffic-from-chrome-firefox-curl-with-wireshark-no-mitm/)
to a file for Wireshark to pick up:

    1. export SSLKEYLOGFILE=~/sharedKeys.txt followed by chromium-browser
    2. chromium-browser --ssl-key-log-file=sharedKeys.txt

Make sure no existing Chrome instances are running or the environment
variable/command-line argument is silently ignored. Setting up Wireshark to use
the file in advance, it'll decrypt traffic flows in. But of course Wireshark may
also decrypt the session later when the key is added. This technique relies on
the fact that TLS only uses public/private keys for initially establishing a
shared symmetric session key. It's these sessions keys that end up in the file.

With Wireshark, it becomes evident that NemLog-in IdP is using HTTP/2. For
easier debugging, force communication to use the regular HTTP protocol.

## References

- [Youtube: Introduction to SAML - Introduction to SAML - Chalktalk on
what is it, how it is
used](https://www.youtube.com/watch?v=S9BpeOmuEz4&list=PLSEDryV9VNWHYtyWrFc_TpMYRwemphDTS)
- [.NET SAML2 Service Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx)
- [Wikipedia: SAML 2.0](https://en.wikipedia.org/wiki/SAML_2.0)

## Contact

Drop me a line at mail@bugfree.dk if you require assistance with
integrating NemLog-in in your application.
