using System.IO;

namespace CAdESLib.Document
{
    /// <summary>In memory representation of a document</summary>
    public class InMemoryDocument : IDocument
    {
        private readonly string? name;

        private readonly byte[] document;

        /// <summary>Create document that retains the data in memory</summary>
        /// <param name="document"></param>
        public InMemoryDocument(byte[] document) : this(document, null)
        {
        }

        public InMemoryDocument(byte[] document, string? name)
        {
            this.document = document;
            this.name = name;
        }

        /// <exception cref="System.IO.IOException"></exception>
        public virtual Stream OpenStream()
        {
            return new MemoryStream(document);
        }

        public virtual string? GetName()
        {
            return name;
        }
    }
}
