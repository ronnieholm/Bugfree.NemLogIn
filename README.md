[websitedemo]: https://github.com/digst/OIOSAML.Net/tree/master/src/dk.nita.saml20/WebsiteDemo
[oiosamlnet]: https://github.com/digst/OIOSAML.Net
[notes]: docs/Introduction-to-asymmetric-cryptography-and-NemLog-in.md
[home]: https://oiosaml-net.dk:20002/Home
[oiosamlnetdoc]: https://github.com/digst/OIOSAML.Net/blob/master/Net%20SAML2%20Service%20Provider%20Framework.docx
[submodules]: https://git-scm.com/book/en/v2/Git-Tools-Submodules
[readme]: https://github.com/digst/OIOSAML.Net/blob/master/readme.md
[oiosamlnetnuget]: https://www.nuget.org/packages/dk.nita.saml20
[breakpoint]: https://stackoverflow.com/questions/2617659/how-can-i-set-a-breakpoint-in-referenced-code-in-visual-studio
[nemloginportal]: https://administration.nemlog-in.dk
[samlmetadata]: https://www.oasis-open.org/committees/download.php/51890/SAML%20MD%20simplified%20overview.pdf
[dnspy]: https://github.com/0xd4d/dnSpy
[windbg]: https://developer.microsoft.com/en-us/windows/hardware/download-windbg
[sessionkeys]: https://www.steffr.ch/inspect-ssl-tls-traffic-from-chrome-firefox-curl-with-wireshark-no-mitm


# Bugfree.NemLogIn

This repository contains

- An ASP.NET MVC demo service provider (SP) adapted from the regular ASP.NET
  [WebSiteDemo][websitedemo] SP part of the [OIOSAML.Net][oiosamlnet]
  authentication solution.
- [Notes on asymmetric cryptography and NemLog-in][notes] to augment official
  NemLog-in documentation which assumes the reader is already familiar with the
  concepts of certificates, encryption, and signing.

**Table of Contents**

<!-- TOC -->

- [Bugfree.NemLogIn](#bugfreenemlogin)
    - [Getting started](#getting-started)
    - [Updating the metadata file for a new service provider](#updating-the-metadata-file-for-a-new-service-provider)
    - [Updating web.config for a new service provider](#updating-webconfig-for-a-new-service-provider)
    - [Authenticate locally using the OIOSAML.Net local IdP](#authenticate-locally-using-the-oiosamlnet-local-idp)
    - [Debugging outside of Visual Studio](#debugging-outside-of-visual-studio)
    - [References](#references)
    - [Contact](#contact)

<!-- /TOC -->

After launching the ASP.NET MVC demo SP, then navigating to
[https://oiosaml-net.dk:20002/home][home]. It looks like this:

![Home](docs/Home.png)

Following the `Goto page requiring authentication` link causes the OIOSAML.Net
library to intercept the request. It redirects the browser to the NemLog-in
identity provider (IdP), or in case of multiple providers, presents the user
with a list of IdPs.

On successful authentication with an IdP, the IdP redirects the browser back to
https://oiosaml-net.dk:20002/RequiresAuthentication, the page originally
requiring authentication. That page lists each SAML attribute returned by the
IdP:

![Requires authentication](docs/RequiresAuthentication.png)

Open the OIOSAML.Net solution and compile it. This generates the assemblies
required by our SP.

Open the Bugfree.NemLogIn.Web SP and compile and run it. It automatically picks
up the assemblies outputted by compiling the OIOSAML.Net solution. The two nita
assemblies were previously added as project references to Bugfree.NemLogIn.Web.

## Getting started

1. Clone the repository, including the submodule:

   ```
   $ git clone --recurse-submodules https://github.com/ronnieholm/Bugfree.NemLogIn.git
   ```

   <!--
      or 
      $ git clone https://github.com/ronnieholm/Bugfree.NemLogIn.git
      $ git submodule init
      $ git submodule update
   -->

   This clones OIOSAML.Net as a [submodule][submodules] to
   ```libs/OIOSAML.Net```. Follow the setup steps outlined in its
   [readme.md][readme] file to setup and run the OIOSAML.Net provided SP and IdP
   before continuing.
   
   Adding OIOSAML.Net in source code form over referencing it through the
   [dk.nita.saml20][oiosamlnetnuget] NuGet package makes for a better debugging
   experience. Without source code, it isn't possible to step through
   OIOSAML.Net library code. Instead of adding dk.nita.saml20 as a submodule, an
   alternative would've been to vendor it. But that makes keeping up-to-date
   with upstream dk.nita.saml20 cumbersome as downstream would need to track
   changes manually.
   
   Within the ```libs/OIOSAML.Net``` folder, view available tagged releases:
   
         $ git tag
         2.0.0
         ...
         release-2.0.2
         release-2.0.3
   
   Current OIOSAML.Net development happens in the master branch.

2. Open dk.nita.saml20.sln in VS and compile.

   Bugfree.NemLogIn.Web references dk.nita.saml20.dll and
   dk.nita.saml20.ext.audit.log4net.dll directly, i.e., not through a project
   reference. If we were to include those projects in the solution, the NuGet
   package manager would suggest updates to packages referenced by dk.nita.saml,
   such as log4net. We want to leave it to dk.nita.saml20 maintainers to manage
   their dependencies.

   To set a breakpoint in [any][breakpoint] third-party assembly referenced
   directly, in VS open a C# file part of the assembly and set a breakpoint.
   Then start the application in debugging mode and execution halts at the
   breakpoint.

3. Open Bugfree.NemLogIn.sln in VS elevated mode (because of required IIExpress
   hostname binding). Starting VS triggers the creation of the .vs folder at the
   solution level. VS infers initial IISExpress configuration by inspecting the
   web projects in the solution and, starting from a template, updates the
   IISExpress configuration file under .vs accordingly.

   VS only adds IISExpress HTTPS bindings for localhost. To run
   Bugfree.NemLogIn.IdP and Bugfree.NemLogIn.Web, HTTPS bindings for
   non-localhost domains must be added to the IISExpress configuration file
   under the .vs folder. The following commands (must be run using `cmd.exe`)
   enables accessing the sites on any domain (using only their port numbers)
   through a wildcard. The domain names and TLS certificates for the IdP and SP
   are reused from the OIOSAML.Net package:

   ```
   "%programfiles%\IIS Express\appcmd.exe" set site "Bugfree.NemLogIn.IdP" /+bindings.[protocol='https',bindingInformation='*:20001:'] /apphostconfig:"%USERPROFILE%\source\repos\Bugfree.NemLogIn\.vs\Bugfree.NemLogIn\config\applicationhost.config"

   "%programfiles%\IIS Express\appcmd.exe" set site "Bugfree.NemLogIn.Web" /+bindings.[protocol='https',bindingInformation='*:20002:'] /apphostconfig:"%USERPROFILE%\source\repos\Bugfree.NemLogIn\.vs\Bugfree.NemLogIn\config\applicationhost.config"
   ```

   If ```appcmd``` fails with a message stating that the binding already exists,
   remove the binding by changing the argument to ```-bindings``` and re-run the
   previous command.   

4. Set projects Bugfree.NemLogIn.IdP and Bugfree.NemLogIn.Web as start projects
   by right-clicking the Bugfree.NemLogIn solution in Solution Explorer, then
   select Properties, and finally "Multiple start projects".   

   Multiple start projects ensure that Bugfree.NemLogIn.Web and any dependent
   web applications are launched together, making Bugfree.NemLogIn.Web fully
   operational after launch.

   Start projects in VS are user specific and thus must be manually set once
   after cloning the repository.

5. For the Bugfree.NemLogIn.IdP and Bugfree.NemLogIn.Web projects, manually set
   their "Start URL". Otherwise, running the projects from VS opens browsers for
   https://localhost:20001 and https://localhost:20002/home instead of
   [https://oiosaml-demoidp.dk:20001](https://oiosaml-demoidp.dk:20001) and
   [https://oiosaml-net.dk:20002](https://oiosaml-net.dk:20002). Without the
   proper domain names, NemLog-in authentication will fail.

   Right-click the Bugfree.NemLogIn.IdP project in Solution Explorer and select
   Properties. Then select the Web tab and enable Start URL by setting it to
   https://oiosaml-demoidp.dk:20001.

   Right-click the Bugfree.NemLogIn.Web project in Solution Explorer and select
   Properties. Then select the Web tab and enable Start URL by setting it to
   https://oiosaml-net.dk:20002.

   Instead of reusing the setup from OIOSAML.Net, we could've created DNS
   entries, TLS certificates, and SAML2 encryption and signing certificates for
   Bugfree.NemLogIn specific versions of these domains. But it isn't worth the
   effort over reusing OIOSAML.Net maintained certificates and setup scripts. 

   Because the Start URLs are user specific with VS, they must be manually set
   once after cloning the repository.

   To authenticate against the NemLog-in test IdP, the root certificate of the
   IdP signing certificate chain of trust must be installed in the Windows
   Certificate Store (it isn't part of the OIOSAML.Net package). Otherwise,
   authentication against the NemLog-in test IdP succeeds but once the result is
   posted back to the SP, a `SecurityTokenValidationException` with message `The
   signature of the incoming message is invalid` is raised. We can disable
   verifying certification chain trust by editing Web.config, adding the
   `omitAssertionSignatureCheck` attribute as below:

     ```xml
     <IDPEndPoints metadata="IdP-metadata">
         <add id="https://saml.test-nemlog-in.dk/" omitAssertionSignatureCheck="true" />
     </IDPEndPoints>
     ```

   Asserting chain of trust should never be disabled in a production setup.

## Updating the metadata file for a new service provider

For easy setup, Bugfree.NemLogIn shares its [metadata][samlmetadata] with the
OIOSAML.Net demo SP. To create a new SP, hosted at a different URL, and using
different certificates for encryption and signing, the SP's metadata must be
updated.

Metadata to upload to the [NemLog-in administration portal][nemloginportal]
is in form of an XML file, and is optionally similarly exposed through a SP's
`metadata.ashx` endpoint (with OIOSAML.Net, the XML file returned by this
endpoint is constructed from configuration settings in `web.config`).
Updating metadata either from the SP's metadata and/or with updating
`web.config`. The steps below focus on modifying the metadata directly:

1. Inside the `EntityDescriptor` element, update the `entityID` attribute to
   match the new environment. While the string resembles a URL, it actually a
   URI. The convention is to prepend "saml" and the type of environment to
   the SP's URI. For a test environment, the URI would be
   https://saml.test.myservice.dk and for production it would be
   https://saml.myservice.dk.
2. Update the two `SingleLogoutService` elements' `Location` and
   `ResponseLocation` attributes to match the base URL of the SP. Then append
   `logout.ashx`, e.g., https://myservice/logout.ashx.
3. Update the `AssertionConsumerService` element's `Location` attribute to match
   the base URL of the SP. Then append login.ashx, e.g.,
   https://myservice/login.ashx.
4. Inside the two `X509Certificate` elements, include the public key of the
   SP's function certificate. In principle, separate public keys may be used for
   encryption and signing, but in practice using the same key seems common
   practice.
5. Update the `ContactPerson` child elements with relevant information for the
   SP.

## Updating web.config for a new service provider

The `web.config` file contains a few environment specific settings that must match
the SP's metadata:

1. The `SigningCertificate` element's `findValue` attribute must be updated
   to the thumbprint of the SP's function certificate. The private key installed in
   the certificate store is what's used for signing and encryption.
2. The inner text of the `Audience` element must match what's in the SP's
   metadata, i.e., the `entityId` value. This value is sent to the IdP and is
   how the IdP identifies the SP calling it. SAML assertions are issued to and
   valid for this audience only.

## Authenticate locally using the OIOSAML.Net local IdP

During SP development, continuously having to login to the NemLog-in test IdP
is a hassle. That's what the local IdP is for. As far as a SP goes, it
shouldn't care about the difference between a local IdP, NemLog-in test IdP,
and NemLog-in production. All a SP cares about is receiving an assertion
with a set of key/value pairs.

## Debugging outside of Visual Studio

On a production server with no Visual Studio, besides enabling the SP's
log4net logging, zero footprint tools such as [dnspy][dnspy] or
[WinDbg][windbg] may be needed. dnspy disassembles IL to C# and supports
setting breakpoints and inspecting the value of variables in the reversed
code. WinDbg is more low-level and solely operates on IL and lower levels.
With these tools, execution may be traced through the SP's code as well as
that of the OIOSAML.Net library.

Setting a breakpoint inside the OIOSAML.Net library enables access to the raw
XML request and response and to follow the request and response flows from
inside the library. In an error cases, seeing where processing fails may be
useful in resolving the issue.

Running a man-in-the-middle proxy such as Fiddler on client and server is
sometimes valuable to see what actually goes over the wire. Fiddler supports
decrypting TLS traffic through a self-signed root certificate. However, even
decrypting TLS traffic, the SAML requests and responses remain encrypted.
They're best decrypted by way of the breakpoint technique mentioned above, or
by flipping a diagnostics flag in `web.config`, causes OIOSAML.Net to dump
the plain text requests/responses.

SAML authentication happens through a number of browser redirection requests.
The SP and IdP provider never communicate directly beyond the "offline"
exchange of metadata. Instead SP and IdP redirect the browser back end forth
during authentication. Therefore the browser's development tools may be
unable to capture the encrypted request/response. Every time a redirect
happens, the network request tab may reset. With Chrome, however, developer
tools provide the `Preserve log` that prevents Chrome from clearing the
network tab upon redirect.

To supplement or replace Fiddler, Wireshark may be used. As communication
takes place over TLS, traffic must be decrypted. Unlike Fiddler, which acts
as a man in the-middle proxy, Wireshark records the traffic as is, invisible
to communicating parties. Wireshark may be the better tool for correlating
traffic on multiple protocol or if/when and IdP employs certificate pinning
(which NemLog-in doesn't).

For Wireshark to decrypt TLS sessions, a browser's shared sessions keys must
be available to it. Chrome and Firefox, but not Edge, supports [dumping
shared session keys][sessionkeys] to a file for Wireshark to pick up:

```
$ export SSLKEYLOGFILE=~/sharedKeys.txt
$ chromium-browser
```

or 

```
$ chromium-browser --ssl-key-log-file=sharedKeys.txt
```

Ensure no existing Chrome instances are running or the environment
variable/command-line argument is silently ignored. Setting up Wireshark to use
the file in advance, it'll decrypt as traffic flows in. But of course Wireshark can
also decrypt the session later when the key file is added. This technique relies on
the fact that TLS only uses public/private keys for initially establishing a
shared symmetric session key. It's these sessions keys that end up in the file.

With Wireshark, it becomes evident that NemLog-in IdP is using HTTP/2. For
easier debugging, perhaps force communication to use the regular HTTP protocol.

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
