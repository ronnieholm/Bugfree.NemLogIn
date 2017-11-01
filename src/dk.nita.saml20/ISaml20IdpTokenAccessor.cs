using System.Xml;

namespace dk.nita.saml20
{
    /// <summary>
    /// Implementors of this interface will be presented with the Xml form of the Saml 2.0 assertion issued by the IdP
    /// before it is translated to a runtime type. 
    /// Implementors MUST NOT alter the xml element or its containing xml document as this may invalidate the xml signature
    /// </summary>
    public interface ISaml20IdpTokenAccessor
    {
        /// <summary>
        /// Read the incoming xml representation of the assertion
        /// </summary>
        /// <param name="assertion">The cml representation of assertion.</param>
        void ReadToken(XmlElement assertion);
    }
}