﻿using System;
using System.Diagnostics;
using System.IdentityModel.Selectors;
using System.Security.Cryptography.X509Certificates;
using dk.nita.saml20.Properties;
using Trace=dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Specification
{
    /// <summary>
    /// Validates a selfsigned certificate
    /// </summary>
    public class SelfIssuedCertificateSpecification : ICertificateSpecification
    {
        /// <summary>
        /// Determines whether the specified certificate is considered valid by this specification.
        /// Always returns true. No online validation attempted.
        /// </summary>
        /// <param name="certificate">The certificate to validate.</param>
        /// <param name="failureReason">If the process fails, the reason is outputted in this variable</param>
        /// <returns>
        /// 	<c>true</c>.
        /// </returns>
        public bool IsSatisfiedBy(X509Certificate2 certificate, out string failureReason)
        {
            X509ChainPolicy chainPolicy = new X509ChainPolicy();
            chainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            X509CertificateValidator defaultCertificateValidator = X509CertificateValidator.CreateChainTrustValidator(false, chainPolicy);

            try
            {
                defaultCertificateValidator.Validate(certificate);
                failureReason = null;
                return true;
            }
            catch (Exception e)
            {
                failureReason = $"Validating with no revocation check failed for certificate '{certificate.Thumbprint}': {e}";
                Trace.TraceData(TraceEventType.Warning, string.Format(Tracing.CertificateIsNotRFC3280Valid, certificate.SubjectName.Name, certificate.Thumbprint, e));
            }

            return false;
        }
    }
}
