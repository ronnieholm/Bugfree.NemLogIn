﻿namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Constants related to the HTTP SOAP binding
    /// </summary>
    public class SOAPConstants
    {
        /// <summary>
        /// Soap action name
        /// </summary>
        public const string SOAPAction = "SOAPAction";
        /// <summary>
        /// Soap body name
        /// </summary>
        public const string SOAPBody = "Body";
        /// <summary>
        /// Soap namespace
        /// </summary>
        public const string SOAPNamespace = "http://schemas.xmlsoap.org/soap/envelope/";

        /// <summary>
        /// Soap envelope begin constant
        /// </summary>
        public const string EnvelopeBegin = "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">";
        /// <summary>
        /// Soap envelope end constant
        /// </summary>
        public const string EnvelopeEnd = "</SOAP-ENV:Envelope>";
        /// <summary>
        /// soap body begin constant
        /// </summary>
        public const string BodyBegin = "<SOAP-ENV:Body>";
        /// <summary>
        /// Soap body end constant
        /// </summary>
        public const string BodyEnd = "</SOAP-ENV:Body>";
    }
}