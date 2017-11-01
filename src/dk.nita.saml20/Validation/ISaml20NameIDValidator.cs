using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Protocol;

namespace dk.nita.saml20.Validation
{
    internal interface ISaml20NameIDValidator
    {
        void ValidateNameID(NameID nameID);
        void ValidateEncryptedID(EncryptedElement encryptedID);
    }
}