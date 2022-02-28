using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// The validation of a certificate may requires the use of OCSP information.
    /// </summary>
    /// <remarks>
    /// The validation of a certificate may requires the use of OCSP information. Theses information can provide from
    /// multiple source (the signature itself, online OCSP server, ...). This interface provide an abstraction for a source
    /// of OCSPResp
    /// </remarks>
    public interface IOcspSource
    {
        /// <summary>
        /// Get and OCSPResp for the given certificate/issuerCertificate couple.
        /// </summary>
        BasicOcspResp GetOcspResponse(X509Certificate certificate, X509Certificate issuerCertificate);
    }
}
