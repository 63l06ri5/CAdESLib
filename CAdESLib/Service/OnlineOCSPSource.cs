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
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private readonly ICAdESServiceSettings settings;

        private string PresetOCSPUri => this.settings.OcspSource;

        /// <summary>
        /// Set the HTTPDataLoader to use for querying the OCSP server.
        /// </summary>
        public IHTTPDataLoader HttpDataLoader { get; set; }

        //jbonilla
        public string OcspUri { get; set; }

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

        public BasicOcspResp GetOcspResponse(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            try
            {
                OcspUri = string.IsNullOrEmpty(PresetOCSPUri) ? GetAccessLocation(certificate, X509ObjectIdentifiers.OcspAccessMethod) : PresetOCSPUri;
                logger.Trace("OCSP URI: " + OcspUri);
                if (OcspUri == null)
                {
                    return null;
                }

                var digestOid = CertificateID.HashSha1;
                try
                {
                    digestOid = new DefaultDigestAlgorithmIdentifierFinder().find(new AlgorithmIdentifier(certificate.SigAlgOid)).Algorithm.Id;
                }
                catch { }

                OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
                // TODO: should use from settings?
                CertificateID certId = new CertificateID(digestOid, issuerCertificate, certificate.SerialNumber);
                var certCertId = certId.ToAsn1Object();
                certId = new CertificateID(new CertID(new AlgorithmIdentifier(certCertId.HashAlgorithm.Algorithm.Id), certCertId.IssuerNameHash, certCertId.IssuerKeyHash, certCertId.SerialNumber));
                ocspReqGenerator.AddRequest(certId);

                var nonce = BigInteger.ValueOf(DateTime.Now.Ticks + Environment.TickCount);
                var oids = new List<DerObjectIdentifier> { OcspObjectIdentifiers.PkixOcspNonce };
                var nonceValue = new DerOctetString(new DerOctetString(nonce.ToByteArray()));
                var values = new List<X509Extension> { new X509Extension(false, nonceValue) };
                ocspReqGenerator.SetRequestExtensions(new X509Extensions(oids, values));

                OcspReq ocspReq = ocspReqGenerator.Generate();
                byte[] ocspReqData = ocspReq.GetEncoded();
                OcspResp ocspResp = new OcspResp(HttpDataLoader.Post(OcspUri, new MemoryStream(ocspReqData)));
                try
                {
                    var respObj = (BasicOcspResp) ocspResp.GetResponseObject();

                    if (!CheckNonce(respObj, nonceValue))
                    {
                        return null;
                    }

                    return respObj;
                }
                catch (ArgumentNullException)
                {
                    // Encountered a case when the OCSPResp is initialized with a null OCSP response...
                    // (and there are no nullity checks in the OCSPResp implementation)
                    return null;
                }
            }
            catch (CannotFetchDataException)
            {
                return null;
            }
            catch (OcspException e)
            {
                logger.Error("OCSP error: " + e.Message);
                return null;
            }
        }

        private string GetAccessLocation(X509Certificate certificate, DerObjectIdentifier
             accessMethod)
        {
            Asn1OctetString authInfoAccessExtensionValue = certificate.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
            if (null == authInfoAccessExtensionValue)
            {
                return null;
            }
            AuthorityInformationAccess authorityInformationAccess;
            DerOctetString oct = (DerOctetString) authInfoAccessExtensionValue;
            authorityInformationAccess = AuthorityInformationAccess.GetInstance((Asn1Sequence) new Asn1InputStream
                (oct.GetOctets()).ReadObject());
            AccessDescription[] accessDescriptions = authorityInformationAccess.GetAccessDescriptions
                ();
            foreach (AccessDescription accessDescription in accessDescriptions)
            {
                logger.Trace("access method: " + accessDescription.AccessMethod);
                bool correctAccessMethod = accessDescription.AccessMethod.Equals(accessMethod);
                if (!correctAccessMethod)
                {
                    continue;
                }
                GeneralName gn = accessDescription.AccessLocation;
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    logger.Trace("not a uniform resource identifier");
                    continue;
                }
                DerIA5String str = (DerIA5String) ((DerTaggedObject) gn.ToAsn1Object()).GetObject();
                string accessLocation = str.GetString();
                logger.Trace("access location: " + accessLocation);
                return accessLocation;
            }
            return null;
        }

        private bool CheckNonce(BasicOcspResp basicResponse, DerOctetString encodedNonce)
        {
            var nonceExt = basicResponse.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce) as DerOctetString;
            if (nonceExt != null)
            {
                if (!nonceExt.Equals(encodedNonce))
                {
                    logger.Error("Different nonce found in response!");
                    return false;
                }
                else
                {
                    logger.Trace("Nonce is good");
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
