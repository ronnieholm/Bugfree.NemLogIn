﻿using System.Collections.Generic;
using System.Web;
using dk.nita.saml20.Identity;
using dk.nita.saml20.session;
using dk.nita.saml20.config;
using dk.nita.saml20.protocol;

namespace dk.nita.saml20.Actions
{
    /// <summary>
    /// This action redirects to a Common Domain Cookie writer endpoint at the IdP.
    /// </summary>
    public class CDCRedirectAction : IAction
    {
        /// <summary>
        /// setting name for the identity provider cookie writer url 
        /// </summary>
        public const string IDPCookieWriterEndPoint = "IDPCookieWriterEndPoint";
        /// <summary>
        /// Local return url setting name
        /// </summary>
        public const string LocalReturnUrl = "LocalReturnUrl";
        /// <summary>
        /// TargetResource query string parameter name.
        /// </summary>
        public const string TargetResource = "TargetResource";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            string idpKey = Saml20PrincipalCache.GetSaml20AssertionLite().Issuer;
            Saml20SignonHandler h = (Saml20SignonHandler) handler;
            IDPEndPoint ep = h.RetrieveIDPConfiguration(idpKey);
            if (ep.CDC.ExtraSettings != null)
            {
                List<KeyValue> values = ep.CDC.ExtraSettings.KeyValues;

                KeyValue idpEndpoint = values.Find(delegate(KeyValue kv) { return kv.Key == IDPCookieWriterEndPoint; });
                if (idpEndpoint == null)
                    throw new Saml20Exception(@"Please specify """ + IDPCookieWriterEndPoint +
                                              @""" in Settings element.");
                
                KeyValue localReturnPoint = values.Find(delegate(KeyValue kv) { return kv.Key == LocalReturnUrl; });
                if(localReturnPoint == null)
                    throw new Saml20Exception(@"Please specify """ + LocalReturnUrl +
                                              @""" in Settings element.");

                string url = idpEndpoint.Value + "?" + TargetResource + "=" + localReturnPoint.Value;

                context.Response.Redirect(url);
            }else
            {
                handler.DoRedirect(context);
            }
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        /// <param name="handler">The handler.</param>
        /// <param name="context">The context.</param>
        /// <param name="IdPInitiated">During IdP initiated logout some actions such as redirecting should not be performed</param>
        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            if (!IdPInitiated)
                handler.DoRedirect(context);
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name = "CDCRedirectAction";

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }
    }
}
