using System;
using System.Collections.Generic;
using System.Text;

namespace CAdESLib.Helpers
{
    public interface IRuntimeValidatingParams
    {
        /// <summary>
        /// Used to validate signature without network
        /// </summary>
        /// <remarks>
        /// Only for internal use. Users assignments doesn't respected
        /// </remarks>
        bool OfflineValidating { get; set; }
    }

    public class RuntimeValidatingParams : IRuntimeValidatingParams
    {
        public bool OfflineValidating { get; set; }
    }
}
