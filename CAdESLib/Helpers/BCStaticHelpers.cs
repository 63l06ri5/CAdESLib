using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Cms;

namespace CAdESLib.Helpers
{
    public class BCStaticHelpers
    {
        public static SignerInformation GetSigner(CmsSignedData cms, SignerID id) => GetSignerInfoByEnumeration(cms.GetSignerInfos(), id) ?? GetSignerInfoByGetFirst(cms.GetSignerInfos(), id);

        public static SignerInformation GetSigner(CmsSignedDataParser cms, SignerID id) => GetSignerInfoByEnumeration(cms.GetSignerInfos(), id) ?? GetSignerInfoByGetFirst(cms.GetSignerInfos(), id);



        public static SignerInformation GetSignerInfoByGetFirst(SignerInformationStore signerInformationStore, SignerID id)
        {
            return signerInformationStore.GetFirstSigner(id);
        }

        public static SignerInformation GetSignerInfoByEnumeration(SignerInformationStore signerInformationStore, SignerID id)
        {
            SignerInformation si = null;
            foreach (SignerInformation s in signerInformationStore.GetSigners())
            {
                if (s.SignerID == id)
                {
                    si = s;
                    break;
                }
            }
            return si;
        }

        public static (string, string) GetSignatureParams(string openKeyOid)
        {
            if (openKeyOid.StartsWith(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id))
            {
                return (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256.Id, RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256.Id);
            }
            else if (openKeyOid.StartsWith(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id))
            {
                return (RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512.Id, RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512.Id);
            }
            else if (openKeyOid.StartsWith(CryptoProObjectIdentifiers.GostR3410x94.Id))
            {
                return (CryptoProObjectIdentifiers.GostR3411.Id, CryptoProObjectIdentifiers.GostR3410x94.Id);
            }
            else if (openKeyOid.StartsWith(CryptoProObjectIdentifiers.GostR3410x2001.Id))
            {
                return (CryptoProObjectIdentifiers.GostR3411.Id, CryptoProObjectIdentifiers.GostR3410x2001.Id);
            }
            else
            {
                return (OiwObjectIdentifiers.IdSha1.Id, openKeyOid);
            }
        }
    }
}
