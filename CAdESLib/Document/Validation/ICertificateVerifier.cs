using Org.BouncyCastle.X509;

namespace CAdESLib.Document.Validation
{
    public interface ICertificateVerifier
    {
        /// <summary>
        /// Return a ValidationContext that contains every information available to validate a X509 Certificate.
        /// </summary>
        IValidationContext GetValidationContext(X509Certificate cert);
    }
}
