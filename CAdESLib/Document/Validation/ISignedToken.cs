using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// A SignedToken is something that is signed.
    /// </summary>
    public interface ISignedToken
    {
        /// <summary>
        /// Name of the signed of this token
        /// </summary>
        X509Name? GetSignerSubjectName();

        /// <summary>
        /// Check if the SignedToken is signed by the issuer
        /// </summary>
        bool IsSignedBy(X509Certificate potentialIssuer);

        /// <summary>
        /// Retrieve certificates from the SignedToken
        /// </summary>
        ICertificateSource? GetWrappedCertificateSource();


        /// <summary>
        /// Root reason to validate the token
        /// </summary>
        List<object?> RootCause { get; }

        /// <summary>
        /// Time of a start of validity
        /// </summary>
        /// <remarks>
        /// ThisUpdate for a revocation data, not before for a certificate, a time stamp for a timestamp
        /// </remarks>
        DateTime ThisUpdate { get; }
    }
}
