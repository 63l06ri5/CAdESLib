using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CAdESLib.Document
{
    /// <summary>A document composed by a CmsSignedData</summary>
    public class CMSSignedDocument : Document
    {
        protected internal CmsSignedData signedData;

        /// <summary>The default constructor for CMSSignedDocument.</summary>
        /// <param name="data"></param>
        public CMSSignedDocument(CmsSignedData data)
        {
            signedData = data;
        }

        public virtual Stream OpenStream()
        {
            Stream output = new MemoryStream();
            DerOutputStream derOuput = new DerOutputStream(output);
            derOuput.WriteObject(Asn1Object.FromByteArray(signedData.GetEncoded()));
            output.Seek(0, SeekOrigin.Begin);
            return output;
        }

        /// <returns>the signedData</returns>
        public virtual CmsSignedData GetCMSSignedData()
        {
            return signedData;
        }

        public virtual string GetName()
        {
            return null;
        }

    }
}
