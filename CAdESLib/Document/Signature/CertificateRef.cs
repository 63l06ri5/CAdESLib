using Org.BouncyCastle.Utilities.Encoders;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Reference a Certificate
    /// </summary>
    public class CertificateRef
    {
        public override string ToString()
        {
            return $"CertificateRef[issuerName={IssuerName},issuerSerial={IssuerSerial},digest={Hex.ToHexString(DigestValue)}]";
        }

        public virtual string DigestAlgorithm { get; set; }

        public virtual byte[] DigestValue { get; set; }

        public virtual string IssuerName { get; set; }

        public virtual string IssuerSerial { get; set; }
    }
}
