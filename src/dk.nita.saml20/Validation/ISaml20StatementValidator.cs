using dk.nita.saml20.Schema.Core;

namespace dk.nita.saml20.Validation
{
    internal interface ISaml20StatementValidator
    {
        void ValidateStatement(StatementAbstract statement);
    }
}