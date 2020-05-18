using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CAdESLib.Document
{
        /// <summary>Interface representing a document (to be signed).</summary>
        /// <remarks>Interface representing a document (to be signed).</remarks>
        public interface Document
        {
            /// <summary>Open a InputStream on the Document content</summary>
            /// <returns></returns>
            Stream OpenStream();

            /// <summary>Return the name of the document</summary>
            /// <returns></returns>
            string GetName();
        }

}
