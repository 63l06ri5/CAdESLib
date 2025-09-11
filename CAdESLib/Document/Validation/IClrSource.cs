using Org.BouncyCastle.X509;
using System.Collections.Generic;
using System;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// The validation of a certificate may require to access some CRL.
    /// </summary>
    /// <remarks>
    /// The validation of a certificate may require to access some CRL. Theses list can be found online, in a cache or even
    /// in the signature itself. This interface provide abstraction of the source of a CRL.
    /// </remarks>
    public interface ICrlSource
    {
        /// <summary>
        /// Finds the request CRL.
        /// </summary>
        IEnumerable<X509Crl> FindCrls(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate);
    }
}
