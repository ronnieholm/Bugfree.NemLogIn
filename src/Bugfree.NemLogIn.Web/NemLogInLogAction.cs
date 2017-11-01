using System.Web;
using dk.nita.saml20.Actions;
using dk.nita.saml20.identity;
using dk.nita.saml20.Logging;
using dk.nita.saml20.protocol;

namespace Bugfree.NemLogIn.Web
{
    public class NemLogInLogAction : IAction
    {
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, dk.nita.saml20.Saml20Assertion assertion)
        {
            // Since FormsAuthentication is used, the user name to log can be found in 
            // context.User.Identity.Name. This user will not be set until after a new 
            // redirect so unfortunately we cannot just log it here, but will have to 
            // do it in MyPage.Load in order to log the local user id.
        }

        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            // Example of logging required by the requirements SLO1 ("Id of internal user account")
            // Since FormsAuthentication is used, the user name to log can be found in 
            // context.User.Identity.Name. The login will be not be cleared until next 
            // redirect due to the way FormsAuthentication works, so we will have to check 
            // Saml20Identity.IsInitialized() too.
            AuditLogging.logEntry(Direction.IN, Operation.LOGOUT, "ServiceProvider logout",
                $"SP local user id: {(context.User.Identity.IsAuthenticated ? context.User.Identity.Name : "none") + " login status: " + Saml20Identity.IsInitialized()}");
        }

        public void SoapLogoutAction(AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            AuditLogging.logEntry(Direction.IN, Operation.LOGOUT, "ServiceProvider SOAP logout",
                $"IdP user id: {userId} login status: {Saml20Identity.IsInitialized()}");
        }

        public string Name
        {
            get { return "NemLogInLogAction"; }
            set { }
        }
    }
}