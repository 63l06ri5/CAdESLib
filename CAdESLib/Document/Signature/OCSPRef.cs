using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Reference an OcspResponse
    /// </summary>
    public class OCSPRef
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly string algorithm;

        private readonly byte[] digestValue;
        
        private readonly bool matchOnlyBasicOCSPResponse;

        public OCSPRef(OcspResponsesID ocsp,  bool matchOnlyBasicOCSPResponse)
            : this(
                    ocsp.OcspRepHash.HashAlgorithm.Algorithm.Id,
                    ocsp.OcspRepHash.GetHashValue(),
                    matchOnlyBasicOCSPResponse)
        {
        }

        public OCSPRef(string algorithm, byte[] digestValue,  bool matchOnlyBasicOCSPResponse)
        {
            this.algorithm = algorithm;
            this.digestValue = digestValue;
            this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
        }

        public virtual bool Match(ICryptographicProvider cryptographicProvider, BasicOcspResp ocspResp)
        {
            byte[] ocspBytes;
            if (matchOnlyBasicOCSPResponse)
            {
                ocspBytes = ocspResp.GetEncoded();
            }
            else
            {
                ocspBytes = OCSPUtils.FromBasicToResp(ocspResp).GetEncoded();
            }

            byte[] computedValue = cryptographicProvider.CalculateDigest(algorithm, ocspBytes);
            nloglogger.Trace("Compare " + Hex.ToHexString(digestValue) + " to computed value " +
                Hex.ToHexString(computedValue) + " of BasicOcspResp produced at " + ocspResp
                .ProducedAt);
            return digestValue.SequenceEqual(computedValue);

        }
    }
}
