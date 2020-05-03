# Bugfree.NemLogIn

This repository contains

- An ASP.NET MVC demo service provider adapted from the regular ASP.NET
  [WebSiteDemo](https://github.com/digst/OIOSAML.Net/tree/master/src/dk.nita.saml20/WebsiteDemo)
  service provider that ships with the
  [OIOSAML.Net](https://github.com/digst/OIOSAML.Net) authentication library.
- [Notes on asymmetric cryptography and
  NemLog-in](docs/Introduction-to-asymmetric-cryptography-and-NemLog-in.txt) to
  augment official NemLog-in documentation which assumes the reader is already
  familar with the concepts of certificates, encryption, and signing.

## Running

Launching the ASP.NET MVC demo service provider and navigating to
https://oiosaml-net.dk:20002/Home, it looks like this:

![Home](docs/Home.png)

Following the "Goto page requirering authentication" link, the OIOSAML.Net
library takes over. The user is redirected to a NemLog-in identity provider, or
in case of multiple providers the user must first select one. After providing
login information, the user is redirected to
https://oiosaml-net.dk:20002/RequiresAuthentication, listing each SAML assertion
returned by the identity provider:

![Requires authentication](docs/RequiresAuthentication.png)

In order to run the MVC demo, the user is assumed to have carried out the [.NET
SAML2 Service Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx)
setup such that the OIOSAML.Net provided local demo and the remote NemLogIn test
identity providers are working with OIOSAML.Net demo service provider.

The following are supplementary notes on how to setup the .NET SAML2 Service
Provider framework.

## Setting up

The following has been testing on Windows Server 2019. First the OIOSAML.Net
[readme.md](https://github.com/digst/OIOSAML.Net/blob/master/readme.md) steps
was followed as is.

## Cloning OIOSAML.Net source from Github

For easier debugging and the ability to step into the OIOSAML.Net code, the
source distribution is preferred over referencing the
[Nuget](https://www.nuget.org/packages/dk.nita.saml20) package.

To clone and view the availble releases (current development takes place in
master):

    % git clone https://github.com/digst/OIOSAML.Net.git
    % git tag
    2.0.0
    ...
    release-2.0.2
    release-2.0.3    

If you're not on a release tag, make a note of the commit hash used in you
solution.

## Copying projects from OIOSAML.Net into Bugfree.NemLogIn.Web

To use NemLog-in from source, we must 

   1. Copy dk.nita.saml20 and dk.nita.saml20.ext.audit.log4net projects from the
      Git repository into our solution. If the directories already exist, first
      remove those. Simply overriding the folder structures will not remove any
      files no longer part of OIOSAML.Net.

   2. The dk.nita.saml20 and dk.nita.saml20.ext.audit.log4net projects projects
      cannot compile outside the OIOSAML.Net solution unless we append the contents
      of src\dk.nita.saml20\CommonAssemblyInfo.cs to the projects' AssemblyInfo.cs
      files. Instead of maintaining version attributes in two places, OIOSAML.Net
      refers to a common location which after copying the projecs leads to the
      following compiler error:

      error CS2001: Source file 'Bugfree.NemLogIn\src\dk.nita.saml20\..\CommonAssemblyInfo.cs' could not be found.

      After copying the below lines (may be different from your version of
      OIOSAML.Net) to the existing AssemblyInfo.cs files:

      ```
      // Ronnie Holm: Copied from CommonAssemblyInfo.cs
      [assembly: AssemblyVersion("2.0.2.0")]
      [assembly: AssemblyFileVersion("2.0.2.0")]
      [assembly: AssemblyInformationalVersion("2.0.2.0")]
      ```

      Delete from projects the reference to CommonAssemblyInfo.cs.

   3. Finally, Bugfree.NemLogIn.Web must be setup to reference the dk.nita.saml20
      and dk.nita.saml20.ext.audit.log4net projects.

## Setting up Bugfree.NemLogIn.Web to use OIOSAML.Net

The following supplements the steps from [.NET SAML2 Service Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx),
Section 6.1 (do note that a one-time keycard is required to log onto the
NemLogIn test environment, but not with the Demo IdP).

  1. Copy the IdP-metadata files from
     OIOSAML.Netsrc\dk.nita.saml20\WebsiteDemo\idp-metadata into
     \src\Bugfree.NemLogIn.Web\IdP-metadata. This enables the service provider
     to communicate with the local demo and remote IdPs.

  2. To test against the NemLog-in test IdP, the IP at which the service
     provider is running must be whitelisted with Nets' certificate revocation
     list server. Otherwise, login with the IdP will succeed but once the result
     is posted back to the service provider, certificate used to sign the IdP
     response cannot be verified, causing an exception. Testing from a
     non-whitelisted IP, we can disable verifying certification chain trust. We
     do this by editing Web.config, adding the omitAssertionSignatureCheck:

     ```
     <IDPEndPoints metadata="IdP-metadata">
         <add id="https://saml.test-nemlog-in.dk/" omitAssertionSignatureCheck="true" />
     </IDPEndPoints>
     ```
	 
  3. The MVC application must be accessible at https://oiosaml-net.dk:20002 for
     the login process to succeed (since the service provider uses the
     OIOSAML.Net demo service provider's metadata and certificates).
     
     For some reason, even though oiosaml-net.dk is mapped to 127.0.0.1 in the
     hosts file, IISExpress may not respond to requests to oiosaml-net.dk.
     Opening this URL will result in an error message in the browser:

     ```
     Bad Request - Invalid Hostname
     HTTP Error 400. The request hostname is invalid.
     ```

     With Visual Studio 2019, the IISExpress config file is dynamically
     generated each time the project is loaded. It's stored in
     src\.vs\config\applicationhost.config. To make IISExpress respond to
     requests for oiosaml-net.dk, open this file and look for the line below:

     ```
     <binding protocol="https" bindingInformation="*:20002:localhost" />
     ```

     and substitute it with
 
     ```
     <binding protocol="https" bindingInformation="*:20002:*" />
     ```

   Now IISExpress to respond to any domain on port 20002, not just
   https://localhost:20002.

## Develop locally by using the OIOSAML.Net local IdP:

During service provider development, continuously having to log into the
NemLog-in test IdP is a hassle. Instead, either use the local identity provider.
This way, any assertion returned by the actual NemLog-in IdP can be changed in a
moment, exercising different code paths.

## Updating the metadata file for a new service provider

To make setup easy, Bugfree.NemLogIn shares its metadata with the OIOSAML.Net
demo service. If we were to create a new service provider, hosted at a different
URL and using different certificates for encryption and signing, the service
provider's metadata requires modification.

Metadata is updated by making changes to the XML file directly. Metadata is
available directly in the file system or downloadable through the service's
metadata.ashx endpoint. After modifying the metadata, the file must be uploaded
through the (NemLog-in administration
portal)[https://administration.nemlog-in.dk]. Everyone with an employee NemID
can be granted access by the company administrator to upload new metadata.

Starting from the demo service provider's metadata, here're the parts that
require substitution to work with a new service provider:

  1. Inside the EntityDescriptor element, update the entityID attribute to match
     the new environment. While the string resembles a URL, it doesn't have to
     be a valid URL -- it's a URI not a URL. The convention is to prepend "saml"
     and the type of environment to the service's URI. For a test environment,
     the URI would be https://saml.test.myservice.dk and for production it would
     be https://saml.myservice.dk.

  2. Update the two SingleLogoutService elements by changing the Location and
     ResponseLocation attributes to match the base URL of the service. Then
     append logout.ashx, e.g., https://myservice/logout.ashx.

  3. Update the AssertionConsumerService element's Location attribute to match
     the base URL of your service. Then append login.ashx, e.g.,
     https://myservice/login.ashx.

  4. Inside the two X509Certificate elements, paste in the public key of the
     service's certificate. In principle, separate public keys could be used for
     encryption and signing, but in practice using the same key seems common
     practice.

  5. Update the ContactPerson child elements with relevant information for the
     service.

## Updating the Web.config file for a new service provider

The Web.config file contains a few environment specific settings that must match
the service's metadata:

  1. The SigningCertificate element's findValue attribute must be updated to the
     thumbprint of the service's certificate. The private key installed in the
     certificate store is what's used for signing.

  2. The inner text of the Audience element must match what's in the service's
     metadata, i.e., the entityId value. This value is sent to the IdP and is
     how the IdP identifies the service provider calling it, and SAML assertions
     are issued to the specific audience.

## Debugging on a server without Visual Studio

On a production server with no Visual Studio installed, zero footprint tools
such as [dnspy](https://github.com/0xd4d/dnSpy) or
[WinDbg](https://developer.microsoft.com/en-us/windows/hardware/download-windbg)
may be useful for tracing code execution. dnspy can disassemble IL to C# and
supports setting breakpoints and inspecting the value of variables based on C#
reverse engineered from IL. WinDbg, on the other hand, is more low-level and
solely operates at IL and lower levels. With these tools, execution may be
traced through the service provider's code as well as that of the OIOSAML.Net
component.

Setting breakpoints inside the OIOSAML.Net component enables access to the raw
XML request and response and to follow request and response flows from inside
the library. In error cases, seeing where processing fails may be useful in
resolving the issue.

A tool such as Fiddler also comes in handy on the server and client. Sometimes
we want to see what actually goes over the wire by having Fiddler decrypt the
SSL traffic. However, even with Fiddler decrypting the TLS traffic, SAML
requests and responses remain encrypted. They're best decrypting through the
breakpoint technique mentioned above. 

SAML authentication happens through a numbr of browser redirection requests. The
service provider and IdP provider don't communicate directly. Instead they each
ask the browser to redirect somewhere else. This means that the browser's F12
development tools aren't useful is tracing requests and responses. Every time a
redirect takes place, the network request tab is cleared.

To supplement or replace a Fiddler, Wireshark may be used. As communication
happens over TLS, we must decrypt the trafic. Unlike Fiddler which acts as  a
man-in-the-middle proxy server, which will not work in cases where certificate
pinning is employeed, Wireshark records the traffic as is, invisible to
communicating parties.

In order for Wireshark to decrypt TLS sessions, the browser's shared sessions
keys must be available to Wireshark. Chrome and Firefox, but not Edge, supports
[dumping shared session
keys](https://www.steffr.ch/inspect-ssl-tls-traffic-from-chrome-firefox-curl-with-wireshark-no-mitm/)
to a file for Wireshark to pick up:


    1. export SSLKEYLOGFILE=~/sharedKeys.txt followed by chromium-browser
    2. chromium-browser --ssl-key-log-file=sharedKeys.txt

Make sure no existing Chrome instances are running or the environment
variable/command-line argument is silently ignored.

If you setup Wireshark to use the file in advance, it'll decrypt as traffic
flows in. But of course Wireshark can also decrypt the session later when the
key is added.

NemLog-in is using HTTP2. For easier debugging, force it to HTTP1.

## Troubleshooting

### Page shows "Saml20Indentity not initialized" error message

The application has lost track that the user is logged in. If we logout by
navigating to https://oiosaml-net.dk:20002/logout.ashx and back to a page
requirering authentication, OIOSAML.Net redirects the browser to the NemLog-in
IdP which oftentimes determines that the user is still logged in. The IdP then
redirects the browser back to the original page without the need for explicitly
logging in. It's unclear if this error message is a feature or a bug.

## References

- [Youtube: Introduction to SAML - Introduction to SAML - Chalktalk on
what is it, how it is
used](https://www.youtube.com/watch?v=S9BpeOmuEz4&list=PLSEDryV9VNWHYtyWrFc_TpMYRwemphDTS)

- [.NET SAML2 Service Provider
Framework](https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx)

## Contact

Drop me a line at mail@bugfree.dk if you require assistance with
integrating NemLog-in in your application.
