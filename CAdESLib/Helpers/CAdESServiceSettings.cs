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
    }

    public interface ICertificateSourceSettings
    {
        IList<X509Certificate> TrustedCerts { get; }
    }
}
