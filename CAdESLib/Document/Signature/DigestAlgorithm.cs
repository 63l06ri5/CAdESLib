using System;

namespace CAdESLib.Document.Signature
{
    public sealed class DigestAlgorithm
    {
        public static readonly DigestAlgorithm SHA1 = new DigestAlgorithm("SHA-1", "1.3.14.3.2.26", "SHA1");

        public static readonly DigestAlgorithm SHA256 = new DigestAlgorithm("SHA-256", "2.16.840.1.101.3.4.2.1", "SHA256");

        public static readonly DigestAlgorithm SHA512 = new DigestAlgorithm("SHA-512", "2.16.840.1.101.3.4.2.3", "SHA512");

        private DigestAlgorithm(string name, string oid, string xmlId)
        {
            this.Name = name;
            this.OID = oid;
            this.XMLID = xmlId;
        }

        public DigestAlgorithm(string name, string oid) : this(name, oid, string.Empty) { }

        public static DigestAlgorithm GetByName(string algoName)
        {
            if ("SHA-1".Equals(algoName) || "SHA1".Equals(algoName))
            {
                return SHA1;
            }
            if ("SHA-256".Equals(algoName))
            {
                return SHA256;
            }
            if ("SHA-512".Equals(algoName))
            {
                return SHA512;
            }
            throw new Exception("unsupported algo: " + algoName);
        }

        public string Name { get; private set; }
        public string OID { get; private set; }
        public string XMLID { get; private set; }

        public override int GetHashCode()
        {
            int prime = 31;
            int result = 1;
            result = prime * result + ((Name == null) ? 0 : Name.GetHashCode());
            return result;
        }

        public override bool Equals(object? obj)
        {
            if (this == obj)
            {
                return true;
            }
            if (obj == null)
            {
                return false;
            }
            if (!(obj is DigestAlgorithm))
            {
                return false;
            }
            DigestAlgorithm other = (DigestAlgorithm)obj;
            if (Name == null)
            {
                if (other.Name != null)
                {
                    return false;
                }
            }
            else
            {
                if (!Name.Equals(other.Name))
                {
                    return false;
                }
            }
            return true;
        }
    }
}
