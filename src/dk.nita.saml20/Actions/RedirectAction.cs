﻿using System.Web;
using dk.nita.saml20.protocol;

namespace dk.nita.saml20.Actions
{
    /// <summary>
    /// Performs redirect after login and logout
    /// </summary>
    public class RedirectAction : IAction
    {
        /// <summary>
        /// Default action name
        /// </summary>
        public const string ACTION_NAME = "Redirect";

        /// <summary>
        /// Action performed during login.
        /// </summary>
        /// <param name="handler">The handler initiating the call.</param>
        /// <param name="context">The current http context.</param>
        /// <param name="assertion">The saml assertion of the currently logged in user.</param>
        public void LoginAction(AbstractEndpointHandler handler, HttpContext context, Saml20Assertion assertion)
        {
            handler.DoRedirect(context);
        }

        /// <summary>
        /// Action performed during logout.
        /// </summary>
        /// <param name="handler">The handler.</param>
        /// <param name="context">The context.</param>
        /// <param name="IdPInitiated">During IdP initiated logout some actions such as redirecting should not be performed</param>
        public void LogoutAction(AbstractEndpointHandler handler, HttpContext context, bool IdPInitiated)
        {
            if(!IdPInitiated)
                handler.DoRedirect(context);
        }

        /// <summary>
        /// <see cref="IAction.SoapLogoutAction"/>
        /// </summary>
        public void SoapLogoutAction(AbstractEndpointHandler handler, HttpContext context, string userId)
        {
            // Do nothing
        }

        private string _name;

        /// <summary>
        /// Gets or sets the name of the action.
        /// </summary>
        /// <value>The name.</value>
        public string Name
        {
            get
            {
                return string.IsNullOrEmpty(_name) ? ACTION_NAME : _name;
            }
            set { _name = value; }
        }
    }
}
