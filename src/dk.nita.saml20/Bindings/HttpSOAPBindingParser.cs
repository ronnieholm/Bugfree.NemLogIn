﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;
using dk.nita.saml20.Schema.Core;
using dk.nita.saml20.Schema.Metadata;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;

namespace dk.nita.saml20.Bindings
{
    /// <summary>
    /// Parses messages pertaining to the HTTP SOAP binding.
    /// </summary>
    public class HttpSOAPBindingParser
    {
        /// <summary>
        /// The current input stream
        /// </summary>
        protected Stream _inputStream;
        /// <summary>
        /// The current soap envelope
        /// </summary>
        protected string _soapEnvelope;
        /// <summary>
        /// The current saml message
        /// </summary>
        protected XmlElement _samlMessage;
        /// <summary>
        /// The current logout request
        /// </summary>
        protected LogoutRequest _logoutRequest;

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSOAPBindingParser"/> class.
        /// </summary>
        /// <param name="httpInputStream">The HTTP input stream.</param>
        public HttpSOAPBindingParser(Stream httpInputStream)
        {
            _inputStream = httpInputStream;
        }

        /// <summary>
        /// Gets the current SAML message.
        /// </summary>
        /// <value>The saml message.</value>
        public XmlElement SamlMessage
        {
            get
            {
                LoadSamlMessage();
                return _samlMessage;
            }
        }

        /// <summary>
        /// Gets the name of the SAML message.
        /// </summary>
        /// <value>The name of the SAML message.</value>
        public string SamlMessageName
        {
            get
            {
                return SamlMessage.LocalName;
            }
        }

        /// <summary>
        /// Determines whether the current message is a LogoutRequest.
        /// </summary>
        /// <returns>
        /// 	<c>true</c> if the current message is a LogoutRequest; otherwise, <c>false</c>.
        /// </returns>
        public bool IsLogoutReqest()
        {
            return SamlMessageName == LogoutRequest.ELEMENT_NAME;
        }

        /// <summary>
        /// Gets the LogoutRequest message.
        /// </summary>
        /// <value>The logout request.</value>
        public LogoutRequest LogoutRequest
        {
            get
            {
                if (!IsLogoutReqest())
                    throw new InvalidOperationException("The Saml message is not an LogoutRequest");
                LoadLogoutRequest();
                return _logoutRequest;
            }
        }

        /// <summary>
        /// Loads the current message as a LogoutRequest.
        /// </summary>
        private void LoadLogoutRequest()
        {
            if (_logoutRequest == null)
            {
                _logoutRequest = Serialization.Deserialize<LogoutRequest>(new XmlNodeReader(SamlMessage));
            }
        }

        /// <summary>
        /// Checks the SAML message signature.
        /// </summary>
        /// <param name="keys">The keys to check the signature against.</param>
        /// <returns></returns>
        public bool CheckSamlMessageSignature(List<KeyDescriptor> keys)
        {
            foreach (KeyDescriptor keyDescriptor in keys)
            {
                KeyInfo ki = (KeyInfo)keyDescriptor.KeyInfo;
                foreach (KeyInfoClause clause in ki)
                {
                    AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);
                    if (key != null && CheckSignature(key))
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks the signature.
        /// </summary>
        /// <param name="key">The key to check against.</param>
        /// <returns></returns>
        private bool CheckSignature(AsymmetricAlgorithm key)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = null;
            doc.PreserveWhitespace = true;
            doc.LoadXml(SamlMessage.OuterXml);
            return XmlSignatureUtils.CheckSignature(doc, key);
        }

        /// <summary>
        /// Gets the status of the current message.
        /// </summary>
        /// <returns></returns>
        public Status GetStatus()
        {
            XmlElement status = (XmlElement)SamlMessage.GetElementsByTagName(Status.ELEMENT_NAME, Saml20Constants.PROTOCOL)[0];
            Status result = null;
            if (status != null)
            {
                result = Serialization.Deserialize<Status>(new XmlNodeReader(status));
            }
            return result;
        }

        /// <summary>
        /// Gets the status of the current message.
        /// </summary>
        /// <returns></returns>
        public NameID GetNameID()
        {
            if (LogoutRequest != null && LogoutRequest.Item != null)
            {
                return LogoutRequest.Item as NameID;
            }
            return null;
        }

        /// <summary>
        /// Loads the SAML message.
        /// </summary>
        protected void LoadSamlMessage()
        {
            if (_samlMessage == null)
            {
                StreamReader reader = new StreamReader(_inputStream);
                _soapEnvelope = reader.ReadToEnd();

                XmlDocument doc = new XmlDocument();
                doc.XmlResolver = null;
                doc.PreserveWhitespace = true;
                doc.LoadXml(_soapEnvelope);

                XmlElement _soapBody = (XmlElement)doc.GetElementsByTagName(SOAPConstants.SOAPBody, SOAPConstants.SOAPNamespace)[0];
                if (_soapBody != null)
                    _samlMessage = (XmlElement)_soapBody.FirstChild;
                else
                    // Artifact resolve special case
                    _samlMessage = doc.DocumentElement;
            }
        }

        /// <summary>
        /// Checks the signature of the message, using a specific set of keys
        /// </summary>
        /// <param name="keys">The set of keys to check the signature against</param>
        /// <returns></returns>
        public bool CheckSignature(IEnumerable<KeyDescriptor> keys)
        {
            foreach (KeyDescriptor keyDescriptor in keys)
            {
                KeyInfo ki = (KeyInfo)keyDescriptor.KeyInfo;

                foreach (KeyInfoClause clause in ki)
                {
                    AsymmetricAlgorithm key = XmlSignatureUtils.ExtractKey(clause);

                    if (key != null && XmlSignatureUtils.CheckSignature(_samlMessage, key))
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>
        /// Determines whether the message is signed.
        /// </summary>
        /// <returns>
        /// 	<c>true</c> if the message is signed; otherwise, <c>false</c>.
        /// </returns>
        public bool IsSigned()
        {
            return XmlSignatureUtils.IsSigned(_samlMessage);
        }
    }
}