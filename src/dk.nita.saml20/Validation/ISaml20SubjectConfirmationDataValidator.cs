using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Validation
{
    internal interface ISaml20SubjectConfirmationDataValidator
    {
        void ValidateSubjectConfirmationData(SubjectConfirmationData data);
    }
}