using CAdESLib.Document.Validation;
using NLog;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System.Linq;

namespace CAdESLib.Document.Signature
{
    /// <summary>
    /// Reference an OcspResponse
    /// </summary>
    public class OCSPRef
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly string algorithm;

        private readonly byte[] digestValue;

        private readonly bool matchOnlyBasicOCSPResponse;

        public OCSPRef(OcspResponsesID ocsp, bool matchOnlyBasicOCSPResponse) : this(ocsp.OcspRepHash.HashAlgorithm.Algorithm.Id, ocsp.OcspRepHash.GetHashValue(), matchOnlyBasicOCSPResponse)
        {
        }

        public OCSPRef(string algorithm, byte[] digestValue, bool matchOnlyBasicOCSPResponse)
        {
            this.algorithm = algorithm;
            this.digestValue = digestValue;
            this.matchOnlyBasicOCSPResponse = matchOnlyBasicOCSPResponse;
        }

        public virtual bool Match(BasicOcspResp ocspResp)
        {
            IDigest digest = DigestUtilities.GetDigest(algorithm);
            byte[] oscpBytes;
            if (matchOnlyBasicOCSPResponse)
            {
                oscpBytes = ocspResp.GetEncoded();
            }
            else
            {
                oscpBytes = OCSPUtils.FromBasicToResp(ocspResp).GetEncoded();
            }
            digest.BlockUpdate(oscpBytes, 0, oscpBytes.Length);
            byte[] computedValue = DigestUtilities.DoFinal(digest);
            logger.Info("Compare " + Hex.ToHexString(digestValue) + " to computed value " +
                Hex.ToHexString(computedValue) + " of BasicOcspResp produced at " + ocspResp
                .ProducedAt);
            return digestValue.SequenceEqual(computedValue);

        }
    }
}
