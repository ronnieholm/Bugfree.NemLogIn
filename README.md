# Bugfree.NemLogIn

This repository consists of an ASP.NET MVC demo application based on
the oiosaml.net authentication library's ASP.NET demo and [notes on
asymmetric cryptography and
NemLog-in](docs/Introduction-to-asymmetric-cryptography-and-NemLog-in.txt). The
MVC application may serve as a starter project for new service
providers while the notes provide a technical overview of
NemLog-in. The NemLog-in documentation assumes the reader is already
familar with certificates, encryption, and signing.

Here's a screenshot of navigating to the MVC application's
https://oiosaml-net.dk:20002/Home. It shows a page accessible to
unauthentication users:

![Home](docs/Home.png)

Following the "Goto page requirering authentication" link, oiosaml.net
takes over and redirects the user to the NemLog-in identity
provider. After providing login information, the user is redirected to
https://oiosaml-net.dk:20002/RequiresAuthentication, listing each SAML
assertion returned by the identity provider:

![Requires authentication](docs/RequiresAuthentication.png)

In order to run the MVC demo, the user is assumed to have carried out
the [.NET SAML2 Service Provider
Framework](https://svn.softwareborsen.dk/oiosaml.net/trunk/Net%20SAML2%20Service%20Provider%20Framework.docx)
setup such that the local and remote identity providers and service
provider are already working.

The following contains supplementary notes on how to setup the .NET
SAML2 Service Provider framework.

## Checking out oiosaml.net source from Subversion

For easier debugging and the ability to step into the oiosaml.net
code, the source distribution is preferred over the
[Nuget](https://www.nuget.org/packages/dk.nita.saml20) package.

We can choose between trunk and any of the release tags from the list
below:

    % svn list https://svn.softwareborsen.dk/oiosaml.net/tags
    release-1.6/
    ...
    release-1.7.9/
    release-2.0.0/

    % svn checkout https://svn.softwareborsen.dk/oiosaml.net/tags/release-2.0.0 oiosaml.net-release-2.0.0

Alternatively we can fetch trunk using:

    % svn checkout https://svn.softwareborsen.dk/oiosaml.net/trunk/ oiosaml.net-trunk
    ...

    % cd oiosaml.net-trunk
    % svn info -r HEAD
    Path: trunk
    URL: https://svn.softwareborsen.dk/oiosaml.net/trunk
    Relative URL: ^/oiosaml.net/trunk
    Repository Root: https://svn.softwareborsen.dk
    Repository UUID: 4e58de57-8926-0410-947e-8945c843cdd7
    Revision: 34533
    Node Kind: directory
    Last Changed Author: mollekas
    Last Changed Rev: 34510
    Last Changed Date: 2017-09-18 10:12:14 +0200 (Mon, 18 Sep 2017)

Trunk receives frequent updates, but may be unstable. Thus, if we're
not on a release tag, make a note of the "Last Changed Rev" and "Last
Changed Date" of the trunk in use.

## Copying projects from oiosaml.net into Bugfree.NemLogIn.Web

To use NemLog-in from source, we must copy from the Subversion
checkout and into our solution the dk.nita.saml20 and
dk.nita.saml20.ext.audit.log4net projects. These projects cannot
compile outside the oiosaml.net solution unless we copy the content of
CommonAssemblyInfo.cs from src\dk.nita.saml20\CommonAssemblyInfo.cs
into the two projects' AssemblyInfo.cs file.

    // Ronnie Holm: Moved from CommonAssemblyInfo.cs
    [assembly: AssemblyVersion("2.0.0.0")]
    [assembly: AssemblyFileVersion("2.0.0.0")]
    [assembly: AssemblyInformationalVersion("2.0.0.0")]

Finally, Bugfree.NemLogIn.Web must be setup to reference the
dk.nita.saml20 and dk.nita.saml20.ext.audit.log4net projects.

## Setting up Bugfree.NemLogIn.Web to use oiosaml.net

The following supplements the steps from [.NET SAML2 Service Provider
Framework](https://svn.softwareborsen.dk/oiosaml.net/trunk/Net%20SAML2%20Service%20Provider%20Framework.docx),
Section 6.1.

  1. Copy the IdP-metadata files from
     oiosaml.net\src\dk.nita.saml20\WebsiteDemo\idp-metadata into
     \src\Bugfree.NemLogIn.Web\IdP-metadata. This enables the service
     provider to communicate with the local and remote IdPs.

  2. To test against the NemLog-in test IdP, the IP at which the
     service provider is running is generally required to be
     whitelisted with Nets' certificate revocation list
     server. Otherwise, login with the IdP will succeed but once the
     result is posted back to the service provider, the certificate
     used to sign the IdP response cannot be verified, causing an
     exception. Testing from a non-whitelisted IP, we must disable
     verifying certification chain trust. We do this by editing
     Web.config, adding the omitAssertionSignatureCheck:

     ```
     <IDPEndPoints metadata="IdP-metadata">
         <add id="https://saml.test-nemlog-in.dk/" omitAssertionSignatureCheck="true" />
     </IDPEndPoints>
     ```
	 
  3. The MVC application must be accessible at
     https://oiosaml-net.dk:20002 for the login process to succeed
     (since the service provider uses the oiosaml.net demo provider's
     metadata and certificates). Even though oiosaml-net.dk is mapped
     to 127.0.0.1 in the hosts file, IISExpress doesn't respond to
     requests from oiosaml-net.dk. Opening this URL will result in an
     error message in the browser:

     ```
     Bad Request - Invalid Hostname
     HTTP Error 400. The request hostname is invalid.
     ```

     With Visual Studio 2017, the IISExpress config file is
     dynamically generated each time the project is loaded. It's
     stored in src\.vs\config\applicationhost.config. To make
     IISExpress respond to requests from the oiosaml.net domain, open
     this file and look for the line below:

     ```
     <binding protocol="https" bindingInformation="*:20002:localhost" />
     ```

     It should be substituted with
 
     ```
     <binding protocol="https" bindingInformation="*:20002:*" />
     ```

   for IISExpress to respond to any domain on port 20002, not just
   https://localhost:20002.

## Develop locally by dependency-injecting NemLog-in into controllers

During development of a service provider, continuously logging into
the NemLog-in test IdP is a hassle. Instead, use the local identity
provider or dependency inject an object encapsulating the SamlIdentity
into each controller. This way, any property returned by the actual
NemLog-in IdP can be changed in a moment, and code paths exercised.

## Updating the metadata file for a new service provider

For easy setup, Bugfree.NemLogIn shares its metadata with the
oiosaml.net demo service. If we were to create a new service, hosted
at a different URL and using different certificates for encryption and
signing, the service's metadata requires modification.

Metadata is updated by making changes to the XML file
directly. Metadata is available directly in the file system or
downloaded through the service's metadata.ashx endpoint. After
modifying the metadata, the file must be uploaded through the
(NemLog-in administration
portal)[https://administration.nemlog-in.dk]. Everyone with an
employee NemID can be granted access by the company administrator to
upload new metadata.

Starting from the demo service provider's metadata, here're the parts
that needs substitution to work with a new service provider:

  1. Inside the EntityDescriptor element, update the entityID
     attribute to match the new environment. While the string
     resembles a URL, it doesn't have to be a valid URL -- it's a URI
     not a URL. The convention is to prepend "saml" and the type of
     environment to the service's URI. For a test environment, the URI
     would become https://saml.test.myservice.dk and for production it
     would become https://saml.myservice.dk.

  2. Update the two SingleLogoutService elements by changing the
     Location and ResponseLocation attribute to match the base URL of
     the service. Then append logout.ashx, e.g.,
     https://myservice/logout.ashx.

  3. Update the AssertionConsumerService element's Location attribute
     to match the base URL of your service. Then append login.ashx,
     e.g., https://myservice/login.ashx.

  4. Inside the two X509Certificate elements, paste in the public key
     of the service's certificate. In principle, separate public keys
     could be used, but in practice using the same key seems common
     practice.

  5. Update the ContactPerson child elements with relevant information
     for the service.

## Updating the Web.config file for a new service provider

The Web.config file contains a few environment specific settings to
match the service's metadata:

  1. The SigningCertificate element's findValue attribute must be
     updated to the thumbprint of the service's certificate. The
     private key installed in the certificate store is what's used for
     signing.

  2. The inner text of the Audience element must match what's in the
     service's metadata, i.e., the entityId value. This value is sent
     to the IdP and is how the identity provider identifies the
     service provider calling it, and SAML assertions are issued to
     the specific audience.

## Debugging on a server without Visual Studio

In a production environment with no Visual Studio, zero footprint
tools such as [dnspy](https://github.com/0xd4d/dnSpy) or
[WinDbg](https://developer.microsoft.com/en-us/windows/hardware/download-windbg)
may be useful for tracing code executing. dnspy disassembles IL to C#
and supports setting breaking and inspecting the value of variables in
C# without access to the original source. WinDbg on the other hand
works solely at the IL level. Using these tools, it's possible to
follow execution through the service provider's own code as well as
that of the oiosaml.net component.

A tool such as Fiddler may also come in handy on the server and
client. Sometimes we want to see what actually goes over the wire by
having Fiddler decrypt the SSL traffic. Another way of debugging is
setting breakpoints inside the oiosaml.net component. This enables
access to the raw XML request and response and to follow its
processing inside the library. In error cases, seeing where processing
fails is oftentimes useful in resolving the issue. Because even with
Fiddler decrypting the TLS traffic, SAML requests and responses are
still encrypted. 

What we can get from Fiddler is the URLs inside the TCP packets. A
fair bit of browser redirection goes on during the logging process.

## Troubleshooting

### oiosaml.net setup script only supported by Windows 7+

While not explicitly stated, the oiosaml.net install script assumes a
recent Windows version. On Windows 7, the following changes are
required to install the certificates.

Running $PSVersionTable on Windows 7 might report something like this:

    % $PSVersionTable

    Name                           Value
    ----                           -----
    CLRVersion                     2.0.50727.8762
    BuildVersion                   6.1.7601.17514
    PSVersion                      2.0
    WSManStackVersion              2.0
    PSCompatibleVersions           {1.0, 2.0}
    SerializationVersion           1.1.0.1
    PSRemotingProtocolVersion      2.1

With PowerShell 2.0, the $PSScriptRoot variable in
oiosaml.net\setup\setup_prerequisites.ps1 is null, causing a runtime
script failure.

To upgrade PowerShell to a more recent version see [Installing Windows
PowerShell](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell?view=powershell-5.1). Version
5.1 appears the most recent version for Windows 7:

    % $PSVersionTable

    Name                           Value
    ----                           -----
    PSVersion                      5.1.14409.1005
    PSEdition                      Desktop
    PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
    BuildVersion                   10.0.14409.1005
    CLRVersion                     4.0.30319.42000
    WSManStackVersion              3.0
    PSRemotingProtocolVersion      2.3
    SerializationVersion           1.1.0.1

Now the $PSScriptRoot of the installation script is an empty string
rather than null and script execution doesn't fail.

### Import-PfxCertificate cmdlet not available on Windows

The Import-PfxCertificate cmdlet from the
oiosaml.net/setup_prerequisites.ps1 script isn't available onWindows
7, causing script execution failure on the following lines:

    Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\My
    Import-PfxCertificate '..\certificates\demoidp ssl.pfx' -Password $certpassword -CertStoreLocation Cert:\LocalMachine\TrustedPeople

Instead we can use this PowerShell helper function utilizing the .NET
API:

    function Import-PfxCertificate {
        param([String]$certPath,[String]$certRootStore = "localmachine", [String]$certStore = "My", $pfxPass = $null)
        $pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2

        if ($pfxPass -eq $null) {
          $pfxPass = read-host "Password" -assecurestring
        } 

        $pfx.import($certPath, $pfxPass, "Exportable,PersistKeySet")

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
        $store.open("MaxAllowed") 
        $store.add($pfx) 
        $store.close()
      }
    
Then we must specify the full path to the certificate for the function
work:

      Import-PfxCertificate 'oiosaml.net\certificates\demoidp ssl.pfx' LocalMachine My "test1234"
      Import-PfxCertificate 'oiosaml.net\certificates\demoidp ssl.pfx' LocalMachine TrustedPeople "test1234"

### Page shows "Saml20Indentity not initialized" error message

The application has lost track that the user is logged in. If we
logout by navigating to https://oiosaml-net.dk:20002/logout.ashx and
back to a page requirering authentication, oiosaml.net redirects the
browser to the NemLog-in IdP which oftentimes determines that the user
is logged in. The IdP then redirects the browser back to the original
page without the need for explicitly logging in. It's unclear if this
error message is a feature or a bug).

## References

[Youtube: Introduction to SAML - Introduction to SAML - Chalktalk on
what is it, how it is
used](https://www.youtube.com/watch?v=S9BpeOmuEz4&list=PLSEDryV9VNWHYtyWrFc_TpMYRwemphDTS)

[.NET SAML2 Service Provider
Framework](https://svn.softwareborsen.dk/oiosaml.net/trunk/Net%20SAML2%20Service%20Provider%20Framework.docx)

## Contact

Drop me a line at mail@bugfree.dk if you require assistance with
integrating NemLog-in in your application.
