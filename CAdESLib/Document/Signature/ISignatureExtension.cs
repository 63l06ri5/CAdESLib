using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Document.Signature
{
    public interface ISignatureExtension
    {
        /// <summary>
        /// Extend the level of the signatures contained in a document.
        /// </summary>
        Document ExtendSignatures(Document document, Document originalData, SignatureParameters parameters);

    }
}
