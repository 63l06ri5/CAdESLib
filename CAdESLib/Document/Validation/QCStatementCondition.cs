using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X509.Qualified;
using System.IO;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Condition that check a specific QCStatement
    /// </summary>
    [System.Serializable]
    public class QcStatementCondition : Condition
    {
        private readonly string qcStatementId = null;

        /// <summary>
        /// Mandatory for serializable
        /// </summary>
        public QcStatementCondition()
        {
        }

        public QcStatementCondition(string qcStatementId)
        {
            this.qcStatementId = qcStatementId;
        }

        public QcStatementCondition(DerObjectIdentifier qcStatementId)
            : this(qcStatementId?.Id)
        {
        }

        public virtual bool Check(CertificateAndContext cert)
        {
            if (cert is null)
            {
                throw new System.ArgumentNullException(nameof(cert));
            }

            Asn1OctetString qcStatement = cert.Certificate.GetExtensionValue(X509Extensions.QCStatements);
            if (qcStatement != null)
            {
                DerOctetString s = (DerOctetString)qcStatement;
                byte[] content = s.GetOctets();
                using (Asn1InputStream input = new Asn1InputStream(content))
                {
                    DerSequence seq = (DerSequence)input.ReadObject();
                    for (int i = 0; i < seq.Count; i++)
                    {
                        QCStatement statement = QCStatement.GetInstance(seq[i]);
                        if (statement.StatementId.Id.Equals(qcStatementId, System.StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                    return false;
                }
            }
            return false;
        }
    }
}
