using NLog;

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
        private static readonly Logger nloglogger = LogManager.GetCurrentClassLogger();

        private bool offlineValidating = false;
        public bool OfflineValidating
        {
            get
            {
                return offlineValidating;
            }
            set
            {
                offlineValidating = value;
                nloglogger.Trace("Offline mode is " + (offlineValidating ? "on" : "off"));
            }
        }
    }
}
