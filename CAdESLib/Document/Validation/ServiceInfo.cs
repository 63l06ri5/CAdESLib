using System;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// From a validation point of view, a Service is a set of pair ("Qualification Statement", "Condition").
    /// </summary>
    [System.Serializable]
    public class ServiceInfo
    {
        public virtual string Type { get; set; }

        private readonly IDictionary<string, ICondition> qualifiersAndConditions = new Dictionary<string, ICondition>();

        /// <summary>
        /// Add a qualifier and the corresponding condition
        /// </summary>
        public virtual void AddQualifier(string qualifier, ICondition condition)
        {
            qualifiersAndConditions[qualifier] = condition;
        }

        /// <returns>
        /// the qualifiersAndConditions
        /// </returns>
        public virtual IDictionary<string, ICondition> GetQualifiersAndConditions()
        {
            return qualifiersAndConditions;
        }

        /// <summary>
        /// Retrieve all the qualifiers for which the corresponding condition evaluate to true.
        /// </summary>
        public virtual IList<string> GetQualifiers(CertificateAndContext cert)
        {
            IList<string> list = new List<string>();
            foreach (KeyValuePair<string, ICondition> e in qualifiersAndConditions)
            {
                if (e.Value.Check(cert))
                {
                    list.Add(e.Key);
                }
            }
            return list;
        }

        public virtual string TspName { get; set; }

        public virtual string TspTradeName { get; set; }

        public virtual string TspPostalAddress { get; set; }

        public virtual string TspElectronicAddress { get; set; }

        public virtual string ServiceName { get; set; }

        public virtual string CurrentStatus { get; set; }

        public virtual DateTime CurrentStatusStartingDate { get; set; }

        public virtual string StatusAtReferenceTime { get; set; }

        public virtual DateTime StatusStartingDateAtReferenceTime { get; set; }

        public virtual DateTime StatusEndingDateAtReferenceTime { get; set; }

        public virtual bool TlWellSigned { get; set; }
    }
}
