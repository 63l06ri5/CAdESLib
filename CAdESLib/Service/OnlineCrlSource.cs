using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
using NLog;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using X509Extensions = Org.BouncyCastle.Asn1.X509.X509Extensions;

namespace CAdESLib.Service
{
    /// <summary>
    /// Online CRL repository.
    /// </summary>
    /// <remarks>
    /// Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
    /// </remarks>
    public class OnlineCrlSource : ICrlSource
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();
        readonly ICAdESServiceSettings settings;

        private string PresetCRLUri => settings.CrlSource;

        /// <summary>
        /// Set the HTTPDataLoader to use for query the CRL server
        /// </summary>
        public IHTTPDataLoader UrlDataLoader { get; set; }

        //jbonilla
        public string IntermediateAcUrl { get; set; }

        public OnlineCrlSource(ICAdESServiceSettings settings, Func<IHTTPDataLoader> dataLoaderFunc)
        {
            this.settings = settings;
            UrlDataLoader = dataLoaderFunc();
        }

        public virtual IEnumerable<X509Crl> FindCrls(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            var crls = new List<X509Crl>();
            try
            {
                var crlURLs = string.IsNullOrEmpty(PresetCRLUri) ? GetCrlUri(certificate) : new List<string> { PresetCRLUri };
                foreach (var crlURL in crlURLs)
                {
                    logger.Trace("CRL's URL for " + certificate.SubjectDN + " : " + crlURL);
                    if (crlURL != null)
                    {
                        X509Crl crl;
                        if (crlURL.StartsWith("http://") || crlURL.StartsWith("https://"))
                        {
                            crl = GetCrl(crlURL);
                        }
                        else
                        {
                            crl = GetCrlFromFS(crlURL);
                        }

                        if (crl is null)
                        {
                            continue;
                        }

                        crls.Add(crl);

                        return crls;
                    }
                }

                return crls;

            }
            catch (CrlException e)
            {
                logger.Error("error parsing CRL: " + e.Message);
                throw;
            }
            catch (UriFormatException e)
            {
                logger.Error("error parsing CRL: " + e.Message);
                throw;
            }
            catch (CertificateException e)
            {
                logger.Error("error parsing CRL: " + e.Message);
                throw;
            }
        }

        private X509Crl GetCrl(string downloadUrl)
        {
            if (downloadUrl != null)
            {
                try
                {
                    var input = UrlDataLoader.Get(downloadUrl);

                    X509CrlParser parser = new X509CrlParser();
                    X509Crl crl = parser.ReadCrl(input);
                    logger.Trace("CRL size: " + crl.GetEncoded().Length + " bytes");
                    return crl;
                }
                catch (CannotFetchDataException)
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }

        private X509Crl GetCrlFromFS(string downloadUrl)
        {
            if (downloadUrl != null)
            {
                try
                {
                    using var input = File.OpenRead(downloadUrl);
                    X509CrlParser parser = new X509CrlParser();
                    X509Crl crl = parser.ReadCrl(input);
                    logger.Trace("CRL size: " + crl.GetEncoded().Length + " bytes");
                    return crl;
                }
                catch (CannotFetchDataException)
                {
                    return null;
                }
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Gives back the CRL URI meta-data found within the given X509 certificate.
        /// </summary>
        /// <returns>
        /// the CRL URI, or <code>null</code> if the extension is not present.
        /// </returns>
        public virtual List<string> GetCrlUri(X509Certificate certificate)
        {
            var uris = new List<string>();
            Asn1OctetString crlDistributionPointsValue = certificate.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (null == crlDistributionPointsValue)
            {
                return uris;
            }
            Asn1Sequence seq;
            try
            {
                DerOctetString oct;
                //oct = (DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointsValue
                //    )).ReadObject());
                oct = (DerOctetString) crlDistributionPointsValue;
                seq = (Asn1Sequence) new Asn1InputStream(oct.GetOctets()).ReadObject();
            }
            catch (IOException e)
            {
                throw new Exception("IO error: " + e.Message, e);
            }
            CrlDistPoint distPoint = CrlDistPoint.GetInstance(seq);
            DistributionPoint[] distributionPoints = distPoint.GetDistributionPoints();
            foreach (DistributionPoint distributionPoint in distributionPoints)
            {
                DistributionPointName distributionPointName = distributionPoint.DistributionPointName;
                if (DistributionPointName.FullName != distributionPointName.PointType)
                {
                    continue;
                }
                GeneralNames generalNames = (GeneralNames) distributionPointName.Name;
                GeneralName[] names = generalNames.GetNames();
                foreach (GeneralName name in names)
                {
                    if (name.TagNo != GeneralName.UniformResourceIdentifier)
                    {
                        logger.Trace("not a uniform resource identifier");
                        continue;
                    }
                    string str;
                    if (name.ToAsn1Object() is DerTaggedObject taggedObject)
                    {
                        DerIA5String derStr = DerIA5String.GetInstance(taggedObject.GetObject());
                        str = derStr.GetString();
                    }
                    else
                    {
                        DerIA5String derStr = DerIA5String.GetInstance(name.ToAsn1Object());
                        str = derStr.GetString();
                    }
                    if (str != null && (str.StartsWith("http://") || str.StartsWith("https://"))
                        && str.ToUpperInvariant().Contains("CRL")) //jbonilla - El URL del CRL para el BCE está en la tercera posición y solo se puede acceder desde HTTP.
                    {
                        uris.Add(str);
                    }
                    else
                    {
                        logger.Trace("Supports only http:// and https:// protocol for CRL");
                    }
                }
            }

            return uris;
        }
    }
}
