using System;
using System.Collections.Generic;
using Org.BouncyCastle.X509;
using CAdESLib.Helpers;

namespace CAdESLib.Document.Validation
{
    public interface ICertificateVerifier
    {
        /// <summary>
        /// Return a ValidationContext that contains every information available to validate a X509 Certificate.
        /// </summary>
        IValidationContext ValidateCertificate(X509Certificate cert, DateTime validationDate, ICertificateSource optionalCertificateSource, IList<CertificateAndContext> usedCerts, ICrlSource optionalCRLSource = null, IOcspSource optionalOCSPSource = null, ICAdESLogger CadesLogger = null);
    }
}
