using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace CAdESLib.Service
{
    /// <summary>
    /// Online OCSP repository.
    /// </summary>
    /// 	</remarks>
    public class OnlineOcspSource : IOcspSource
    {
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private readonly ICAdESServiceSettings settings;

        private string PresetOCSPUri => this.settings.OcspSource;

        /// <summary>
        /// Set the HTTPDataLoader to use for querying the OCSP server.
        /// </summary>
        public IHTTPDataLoader HttpDataLoader { get; set; }

        public string? OcspUri { get; set; }

        /// <summary>
        /// Create an OCSP source The default constructor for OnlineOCSPSource.
        /// </summary>
        public OnlineOcspSource(ICAdESServiceSettings settings, Func<IHTTPDataLoader> dataLoaderFunc)
        {
            this.settings = settings;
            var dataLoader = dataLoaderFunc();
            dataLoader.TimeOut = 5000;
            dataLoader.ContentType = "application/ocsp-request";
            dataLoader.Accept = "application/ocsp-response";
            HttpDataLoader = dataLoader;
        }

        public IEnumerable<BasicOcspResp?> GetOcspResponse(
                X509Certificate certificate,
                X509Certificate issuerCertificate,
                DateTime startDate,
                DateTime endDate)
        {
            var result = new List<BasicOcspResp?>();
            try
            {
                var certAccessLocation = GetAccessLocation(certificate, X509ObjectIdentifiers.OcspAccessMethod);
                OcspUri = !string.IsNullOrEmpty(certAccessLocation)
                    ?
                    (!string.IsNullOrEmpty(PresetOCSPUri) ? PresetOCSPUri : certAccessLocation)
                    : null;
                nloglogger.Trace("OCSP URI: " + OcspUri);
                if (OcspUri == null)
                {
                    return result;
                }

                var digestOid = CertificateID.HashSha1;
                try
                {
                    digestOid = new DefaultDigestAlgorithmIdentifierFinder().find(new AlgorithmIdentifier(certificate.CertificateStructure.SignatureAlgorithm.Algorithm)).Algorithm.Id;
                }
                catch { }

                OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
                CertificateID certId = new CertificateID(digestOid, issuerCertificate, certificate.SerialNumber);
                var certCertId = certId.ToAsn1Object();
                certId = new CertificateID(new CertID(new AlgorithmIdentifier(certCertId.HashAlgorithm.Algorithm), certCertId.IssuerNameHash, certCertId.IssuerKeyHash, certCertId.SerialNumber));
                ocspReqGenerator.AddRequest(certId);

                var nonce = BigInteger.ValueOf(DateTime.UtcNow.Ticks + Environment.TickCount);
                var oids = new List<DerObjectIdentifier> { OcspObjectIdentifiers.PkixOcspNonce };
                var nonceValue = new DerOctetString(new DerOctetString(nonce.ToByteArray()));
                var values = new List<X509Extension> { new X509Extension(false, nonceValue) };
                ocspReqGenerator.SetRequestExtensions(new X509Extensions(oids, values));

                OcspReq ocspReq = ocspReqGenerator.Generate();
                byte[] ocspReqData = ocspReq.GetEncoded();
                OcspResp ocspResp = new OcspResp(HttpDataLoader.Post(OcspUri, new MemoryStream(ocspReqData)));
                try
                {
                    var respObj = (BasicOcspResp)ocspResp.GetResponseObject();

                    if (!CheckNonce(respObj, nonceValue))
                    {
                        return result;
                    }

                    if (respObj.ProducedAt.CompareTo(respObj.Responses[0].ThisUpdate) < 0)
                    {
                        nloglogger.Error($"onlineocsp: ProducedAt < ThisUpdate, producedAt={respObj.ProducedAt}, thisUpdate={respObj.Responses[0].ThisUpdate}");
                        return result;
                    }
                    else if (!respObj.IsValid(startDate, endDate))
                    {
                        nloglogger.Error($"onlineocsp: not valid: validationPeriod={startDate}-{endDate}, producedAt={respObj.ProducedAt}, thisUpdate={respObj.Responses[0].ThisUpdate}, nextUpdate={respObj.Responses[0].NextUpdate}");
                        return result;
                    }

                    result.Add(respObj);

                    return result;
                }
                catch (ArgumentNullException)
                {
                    // Encountered a case when the OCSPResp is initialized with a null OCSP response...
                    // (and there are no nullity checks in the OCSPResp implementation)
                    return result;
                }
            }
            catch (CannotFetchDataException)
            {
                return result;
            }
            catch (OcspException e)
            {
                nloglogger.Error("OCSP error: " + e.Message);
                return result;
            }
        }

        private string? GetAccessLocation(X509Certificate certificate, DerObjectIdentifier accessMethod)
        {
            Asn1OctetString authInfoAccessExtensionValue = certificate.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
            if (null == authInfoAccessExtensionValue)
            {
                return null;
            }
            AuthorityInformationAccess authorityInformationAccess;
            DerOctetString oct = (DerOctetString)authInfoAccessExtensionValue;
            authorityInformationAccess = AuthorityInformationAccess.GetInstance((Asn1Sequence)new Asn1InputStream
                (oct.GetOctets()).ReadObject());
            AccessDescription[] accessDescriptions = authorityInformationAccess.GetAccessDescriptions
                ();
            foreach (AccessDescription accessDescription in accessDescriptions)
            {
                nloglogger.Trace("access method: " + accessDescription.AccessMethod);
                bool correctAccessMethod = accessDescription.AccessMethod.Equals(accessMethod);
                if (!correctAccessMethod)
                {
                    continue;
                }
                GeneralName gn = accessDescription.AccessLocation;
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    nloglogger.Trace("not a uniform resource identifier");
                    continue;
                }
                DerIA5String str = (DerIA5String)((DerTaggedObject)gn.ToAsn1Object()).GetObject();
                string accessLocation = str.GetString();
                nloglogger.Trace("access location: " + accessLocation);
                return accessLocation;
            }
            return null;
        }

        private bool CheckNonce(BasicOcspResp basicResponse, DerOctetString encodedNonce)
        {
            if (basicResponse is null)
            {
                throw new ArgumentNullException(nameof(basicResponse));
            }

            if (encodedNonce is null)
            {
                throw new ArgumentNullException(nameof(encodedNonce));
            }

            var nonceExt = basicResponse.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce) as DerOctetString;
            if (nonceExt != null)
            {
                if (!nonceExt.Equals(encodedNonce))
                {
                    nloglogger.Error("Different nonce found in response!");
                    return false;
                }
                else
                {
                    nloglogger.Trace("Nonce is good");
                    return true;
                }
            }
            // https://tools.ietf.org/html/rfc5019
            // Clients that opt to include a nonce in the
            // request SHOULD NOT reject a corresponding OCSPResponse solely on the
            // basis of the nonexistent expected nonce, but MUST fall back to
            // validating the OCSPResponse based on time.
            return false;
        }
    }
}
