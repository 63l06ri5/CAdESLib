﻿using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using NLog;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
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
                logger.Info("OCSP URI: " + OcspUri);
                if (OcspUri == null)
                {
                    return null;
                }
                OcspReqGenerator ocspReqGenerator = new OcspReqGenerator();
                CertificateID certId = new CertificateID(CertificateID.HashSha1, issuerCertificate, certificate.SerialNumber);
                ocspReqGenerator.AddRequest(certId);
                OcspReq ocspReq = ocspReqGenerator.Generate();
                byte[] ocspReqData = ocspReq.GetEncoded();
                OcspResp ocspResp = new OcspResp(HttpDataLoader.Post(OcspUri, new MemoryStream(ocspReqData)));
                try
                {
                    return (BasicOcspResp)ocspResp.GetResponseObject();
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
            DerOctetString oct = (DerOctetString)authInfoAccessExtensionValue;
            authorityInformationAccess = AuthorityInformationAccess.GetInstance((Asn1Sequence)new Asn1InputStream
                (oct.GetOctets()).ReadObject());
            AccessDescription[] accessDescriptions = authorityInformationAccess.GetAccessDescriptions
                ();
            foreach (AccessDescription accessDescription in accessDescriptions)
            {
                logger.Info("access method: " + accessDescription.AccessMethod);
                bool correctAccessMethod = accessDescription.AccessMethod.Equals(accessMethod);
                if (!correctAccessMethod)
                {
                    continue;
                }
                GeneralName gn = accessDescription.AccessLocation;
                if (gn.TagNo != GeneralName.UniformResourceIdentifier)
                {
                    logger.Info("not a uniform resource identifier");
                    continue;
                }
                DerIA5String str = (DerIA5String)((DerTaggedObject)gn.ToAsn1Object()).GetObject();
                string accessLocation = str.GetString();
                logger.Info("access location: " + accessLocation);
                return accessLocation;
            }
            return null;
        }
    }
}
