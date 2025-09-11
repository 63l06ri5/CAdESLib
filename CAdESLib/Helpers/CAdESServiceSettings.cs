using CAdESLib.Document.Signature;
using Org.BouncyCastle.X509;
using System.Collections.Generic;

namespace CAdESLib.Helpers
{

    public interface ICAdESServiceSettings : ITSPServiceSettings, IOcspServiceSettings, ICrlServiceSettings, ICertificateSourceSettings
    {
        SignaturePackaging SignaturePackaging { get; }
        SignatureProfile SignatureProfile { get; }
        SignatureType SignatureType { get; }
    }

    public interface ITSPServiceSettings
    {
        string TspSource { get; }
        string TspUsername { get; }
        string TspPassword { get; }
        string TspDigestAlgorithmOID { get; }
    }

    public interface IOcspServiceSettings
    {
        string OcspSource { get; }
    }

    public interface ICrlServiceSettings
    {
        string CrlSource { get; }

        IList<X509Crl> Crls { get; }
    }

    public interface ICertificateSourceSettings
    {
        IList<X509Certificate> TrustedCerts { get; }
    }

    public class CAdESServiceSettings : ICAdESServiceSettings
    {
        public SignaturePackaging SignaturePackaging { get; set; }

        public SignatureProfile SignatureProfile { get; set; }

        public SignatureType SignatureType { get; set; }

        public string TspSource { get; set; } = string.Empty;

        public string TspUsername { get; set; } = string.Empty;

        public string TspPassword { get; set; } = string.Empty;

        public string TspDigestAlgorithmOID { get; set; } = string.Empty;

        public string OcspSource { get; set; } = string.Empty;

        public string CrlSource { get; set; } = string.Empty;

        public IList<X509Certificate> TrustedCerts { get; set; } = new List<X509Certificate>();

        public IList<X509Crl> Crls { get; set; } = new List<X509Crl>();
    }
}
