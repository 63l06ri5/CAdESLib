using Org.BouncyCastle.Utilities.Date;
using System.Collections.Generic;

namespace CAdESLib.Document.Validation
{
    /// <summary>
    /// Contains trusted list information relevant to a certificate
    /// </summary>
    public class TrustedListInformation
    {
        private readonly ServiceInfo trustService;

        public TrustedListInformation(ServiceInfo ts)
        {
            trustService = ts;
        }

        /// <returns>
        /// the serviceWasFound
        /// </returns>
        public virtual bool IsServiceWasFound => trustService != null;

        /// <returns></returns>
        public virtual string? TSPName
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.TspName;
            }
        }

        /// <returns></returns>
        public virtual string? TSPTradeName
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.TspTradeName;
            }
        }

        /// <returns></returns>
        public virtual string? TSPPostalAddress
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.TspPostalAddress;
            }
        }

        /// <returns></returns>
        public virtual string? TSPElectronicAddress
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.TspElectronicAddress;
            }
        }

        /// <returns></returns>
        public virtual string? ServiceType
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.Type;
            }
        }

        /// <returns></returns>
        public virtual string? ServiceName
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return trustService.ServiceName;
            }
        }

        /// <returns></returns>
        public virtual string? CurrentStatus
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                var status = trustService.CurrentStatus;
                var slashIndex = status?.LastIndexOf('/') ?? 0;
                if (slashIndex > 0 && slashIndex < status!.Length - 1)
                {
                    status = status[(slashIndex + 1)..];
                }
                return status;
            }
        }

        /// <returns></returns>
        public virtual DateTimeObject? CurrentStatusStartingDate
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return new DateTimeObject(
                    trustService.CurrentStatusStartingDate);
            }
        }

        /// <returns></returns>
        public virtual string? StatusAtReferenceTime
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                var status = trustService.StatusAtReferenceTime;
                var slashIndex = status?.LastIndexOf('/') ?? 0;
                if (slashIndex > 0 && slashIndex < status!.Length - 1)
                {
                    status = status[(slashIndex + 1)..];
                }
                return status;
            }
        }

        public virtual DateTimeObject? StatusStartingDateAtReferenceTime
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                return new DateTimeObject(
                    trustService.StatusStartingDateAtReferenceTime);
            }
        }

        /// <summary>
        /// Is the Trusted List well signed
        /// </summary>
        /// <returns></returns>
        public virtual bool IsWellSigned
        {
            get
            {
                if (trustService == null)
                {
                    return false;
                }
                return trustService.TlWellSigned;
            }
        }

        /// <summary>
        /// Return the list of condition associated to this service
        /// </summary>
        /// <returns></returns>
        public virtual IList<QualificationElement>? QualitificationElements
        {
            get
            {
                if (trustService == null)
                {
                    return null;
                }
                IList<QualificationElement> elements = new List<QualificationElement>();
                foreach (KeyValuePair<string, ICondition> e in trustService.GetQualifiersAndConditions())
                {
                    elements.Add(new QualificationElement(e.Key, e.Value));
                }
                return elements;
            }
        }
    }
}
