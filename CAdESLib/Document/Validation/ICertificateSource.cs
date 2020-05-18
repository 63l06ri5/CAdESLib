using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// The validation of a certificate require to access some other certificate from multiple source (Trusted List, trust
    /// store, the signature itself).
    /// </summary>
    /// <remarks>
    /// The validation of a certificate require to access some other certificate from multiple source (Trusted List, trust
    /// store, the signature itself). This interface provides abstraction for accessing a certificate, regardless of the
    /// source.
    /// </remarks>
    public interface ICertificateSource
    {
        /// <summary>
        /// Give all certificate corresponding to a subject name.
        /// </summary>
        /// <remarks>
        /// Give all certificate corresponding to a subject name. Regardless of other criteria, like validity.
        /// </remarks>
        /// <returns>
        /// A list of certificates (and their respective context) corresponding to the subjectName. Never return
        /// null.
        /// </returns>
        IList<CertificateAndContext> GetCertificateBySubjectName(X509Name subjectName);
    }
}
