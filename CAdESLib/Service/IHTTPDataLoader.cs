using System.Collections.Generic;
using System.IO;

namespace CAdESLib.Service
{
    /// <summary>
    /// Component that permit to retrieve and post data using HTTP.
    /// </summary>
    public interface IHTTPDataLoader
    {
        /// <summary>
        /// Execute a HTTP GET operation
        /// </summary>
        Stream Get(string URL);

        /// <summary>
        /// Execute a HTTP POST operation
        /// </summary>
        Stream Post(string URL, Stream content);

        string ContentType { get; set; }
        string Accept { get; set; }
        int TimeOut { get; set; }
        Dictionary<string, string> Headers { get; set; }
    }
}
