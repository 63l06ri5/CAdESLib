using CAdESLib.Helpers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;
using System;

namespace CAdESLib.Service
{
    /// <summary>
    /// Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
    /// </summary>
    public class OnlineTspSource : TSAClientBouncyCastle, ITspSource
    {
        private readonly ITSPServiceSettings settings;
        public OnlineTspSource(ICAdESServiceSettings settings)
        {
            this.settings = settings;
        }

        public override string TsaURL
        {
            get
            {
                return settings.TspSource;
            }
        }

        public override string TsaUsername
        {
            get
            {
                return settings.TspUsername;
            }
        }

        public override string TsaPassword
        {
            get
            {
                return settings.TspPassword;
            }
        }

        public override string TsaDigestAlgorithmOID
        {
            get
            {
                return settings.TspDigestAlgorithmOID ?? DEFAULTHASHALGORITHMOID;
            }
        }


        public virtual TimeStampResponse GetTimeStampResponse(string digestAlgorithmOID, byte[] digest)
        {
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.SetCertReq(true);
            // tsqGenerator.setReqPolicy("1.3.6.1.4.1.601.10.3.1");
            BigInteger nonce = BigInteger.ValueOf(DateTime.Now.Ticks + Environment.TickCount);
            TimeStampRequest request = tsqGenerator.Generate(digestAlgorithmOID, digest, nonce);
            byte[] requestBytes = request.GetEncoded();

            // Call the communications layer
            var respBytes = GetTSAResponse(requestBytes);

            // Handle the TSA response
            return new TimeStampResponse(respBytes);

        }
    }
}
