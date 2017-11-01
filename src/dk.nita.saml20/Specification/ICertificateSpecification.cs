﻿using System.Security.Cryptography.X509Certificates;

namespace dk.nita.saml20.Specification
{
    /// <summary>
    /// Specification interface for certificate validation
    /// </summary>
    public interface ICertificateSpecification 
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid by this specification.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="failureReason">If the process fails, the reason is outputted in this variable</param>
        /// <returns>
        /// 	<c>true</c> if valid; otherwise, <c>false</c>.
        /// </returns>
        bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason);
    }
}