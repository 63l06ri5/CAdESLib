using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

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
        X509Name GetSignerSubjectName();

        /// <summary>
        /// Check if the SignedToken is signed by the issuer
        /// </summary>
        bool IsSignedBy(X509Certificate potentialIssuer);

        /// <summary>
        /// Retrieve certificates from the SignedToken
        /// </summary>
        ICertificateSource GetWrappedCertificateSource();


        /// <summary>
        /// Root reason to validate the token
        /// </summary>
        List<object> RootCause { get; }
    }
}
