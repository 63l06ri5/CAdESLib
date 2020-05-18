using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using NLog;
using System.IO;
using CAdESLib.Document.Validation;
using CAdESLib.Helpers;
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

        ICAdESServiceSettings settings;

        private string presetCRLUri => this.settings.CrlSource;

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

        public virtual X509Crl FindCrl(X509Certificate certificate, X509Certificate issuerCertificate)
        {
            try
            {
                string crlURL = string.IsNullOrEmpty(presetCRLUri) ? GetCrlUri(certificate) : presetCRLUri;
                logger.Info("CRL's URL for " + certificate.SubjectDN + " : " + crlURL);
                if (crlURL == null)
                {
                    return null;
                }
                if (crlURL.StartsWith("http://") || crlURL.StartsWith("https://"))
                {
                    return GetCrl(crlURL);
                }
                else
                {
                    return GetCrlFromFS(crlURL);
                    //logger.Info("We support only HTTP and HTTPS CRL's url, this url is " + crlURL);
                    //return null;
                }
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
                    logger.Info("CRL size: " + crl.GetEncoded().Length + " bytes");
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
                    using (var input = File.OpenRead(downloadUrl))
                    {
                        X509CrlParser parser = new X509CrlParser();
                        X509Crl crl = parser.ReadCrl(input);
                        logger.Info("CRL size: " + crl.GetEncoded().Length + " bytes");
                        return crl;
                    }
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
        public virtual string GetCrlUri(X509Certificate certificate)
        {
            Asn1OctetString crlDistributionPointsValue = certificate.GetExtensionValue(X509Extensions.CrlDistributionPoints);
            if (null == crlDistributionPointsValue)
            {
                return null;
            }
            Asn1Sequence seq;
            try
            {
                DerOctetString oct;
                //oct = (DEROctetString)(new ASN1InputStream(new ByteArrayInputStream(crlDistributionPointsValue
                //    )).ReadObject());
                oct = (DerOctetString)crlDistributionPointsValue;
                seq = (Asn1Sequence)new Asn1InputStream(oct.GetOctets()).ReadObject();
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
                GeneralNames generalNames = (GeneralNames)distributionPointName.Name;
                GeneralName[] names = generalNames.GetNames();
                foreach (GeneralName name in names)
                {
                    if (name.TagNo != GeneralName.UniformResourceIdentifier)
                    {
                        logger.Info("not a uniform resource identifier");
                        continue;
                    }
                    string str = null;
                    if (name.ToAsn1Object() is DerTaggedObject)
                    {
                        DerTaggedObject taggedObject = (DerTaggedObject)name.ToAsn1Object();
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
                        return str;
                    }
                    else
                    {
                        logger.Info("Supports only http:// and https:// protocol for CRL");
                    }
                }
            }

            //jbonilla
            #region BCE
            if (certificate.SubjectDN.ToString()
                .Contains("AC BANCO CENTRAL DEL ECUADOR"))
            {
                return IntermediateAcUrl;
            }
            #endregion

            return null;
        }
    }
}
