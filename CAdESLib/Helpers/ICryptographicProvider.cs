using System.IO;
using System.Linq;
using CAdESLib.Document;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;

namespace CAdESLib.Helpers
{
    public interface ICryptographicProvider
    {
        byte[] CalculateDigest(string algorithm, byte[] data);

        bool CheckIntegrity(CmsSignedData cmsSignedData, IDocument? detachedDocument);
    }

    public class BouncyCastleCryptographicProvider : ICryptographicProvider
    {
        public byte[] CalculateDigest(string algorithm, byte[] data)
        {
            var digest = DigestUtilities.GetDigest(algorithm);
            digest.BlockUpdate(data, 0, data.Length);
            return DigestUtilities.DoFinal(digest);
        }

        public bool CheckIntegrity(CmsSignedData cmsSignedData, IDocument? detachedDocument)
        {
            try
            {
                bool ret = false;
                SignerInformation si = cmsSignedData.GetSignerInfos().GetSigners().OfType<SignerInformation>().First();
                if (detachedDocument != null)
                {
                    // Recreate a SignerInformation with the content using a CMSSignedDataParser                   
                    var sp = new CmsSignedDataParser(new CmsTypedStream(detachedDocument.OpenStream()), cmsSignedData.GetEncoded());
                    sp.GetSignedContent().Drain();
                    si = BCStaticHelpers.GetSigner(sp, si.SignerID);
                }
                var signingCertificate = cmsSignedData.GetCertificates(si.SignerID, false).FirstOrDefault(cert => si.SignerID.Match(cert));
                ret = si.Verify(signingCertificate);
                return ret;
            }
            catch (CertificateExpiredException)
            {
                return false;
            }
            catch (CmsException)
            {
                return false;
            }
            catch (IOException)
            {
                return false;
            }
        }
    }
}
