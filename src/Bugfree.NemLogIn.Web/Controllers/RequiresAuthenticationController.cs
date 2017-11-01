using System.Collections.Generic;
using System.Web.Mvc;
using dk.nita.saml20.identity;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Logging;
using dk.nita.saml20.protocol;

namespace Bugfree.NemLogIn.Web.Controllers
{
    public class AssertionModel
    {
        public List<KeyValuePair<string, string>> Assertions { get; private set; }

        public AssertionModel()
        {
            Assertions = new List<KeyValuePair<string, string>>();
        }
    }

    public class RequiresAuthenticationController : Controller
    {
        public ActionResult Index()
        {
            if (Saml20Identity.IsInitialized())
            {
                var model = new AssertionModel();
                foreach (SamlAttribute attribute in Saml20Identity.Current)
                {
                    var key = attribute.Name;
                    var value = attribute.AttributeValue.Length > 0 ? attribute.AttributeValue[0] : "";
                    model.Assertions.Add(new KeyValuePair<string, string>(key, value));
                }

                return View(model);
            }

            return Content("Saml20Indentity not initialized");
        }

        public void Logoff()
        {
            AuditLogging.logEntry(Direction.OUT, Operation.LOGOUTREQUEST, "ServiceProvider logoff requested, local user id: " + System.Web.HttpContext.Current.User.Identity.Name);
            Response.Redirect("/logout.ashx");
        }

        public void Relogin()
        {
            Response.Redirect("/login.ashx?" + Saml20AbstractEndpointHandler.IDPForceAuthn + "=true&ReturnUrl=https://oiosaml-net.dk:20002/RequiresAuthentication");
        }

        public void ReloginPassive()
        {
            Response.Redirect("/login.ashx?" + Saml20AbstractEndpointHandler.IDPIsPassive + "=true&ReturnUrl=https://oiosaml-net.dk:20002/RequiresAuthentication");
        }

        public void ReloginNoForceAuthn()
        {
            Response.Redirect("/login.ashx?ReturnUrl=https://oiosaml-net.dk:20002/RequiresAuthentication");
        }
    }
}