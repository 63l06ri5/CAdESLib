using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{

    /// <summary>
    /// The AIA CertificateSource must be created for each certificate.
    /// </summary>
    /// <remarks>
    /// The AIA CertificateSource must be created for each certificate. The CertificateSourceFactory create such source
    /// provided a X509 Certificate.
    /// </remarks>
    public interface ICertificateSourceFactory
    {
        /// <summary>
        /// Return a new CertificateSource that retrieve certificates according the AIA attribute.
        /// </summary>
        ICertificateSource CreateAIACertificateSource(X509Certificate certificate);
    }

}
