using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace CAdESLib.Service
{
    /// <summary>
    /// Exception when the data cannot be fetched
    /// </summary>
    [System.Serializable]
    public class CannotFetchDataException : Exception
    {

        private readonly Exception cause;

        private readonly string serviceName;

        public CannotFetchDataException(IOException ex, string serviceName)
        {
            cause = ex;
            this.serviceName = serviceName;
        }

        public CannotFetchDataException(WebException ex, string serviceName)
        {
            cause = ex;
            this.serviceName = serviceName;
        }
        public CannotFetchDataException(NotSupportedException ex, string serviceName)
        {
            cause = ex;
            this.serviceName = serviceName;
        }
        public CannotFetchDataException(Exception ex, string serviceName)
        {
            cause = ex;
            this.serviceName = serviceName;
        }
    }
}
