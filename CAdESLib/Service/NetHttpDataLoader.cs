using NLog;
using Org.BouncyCastle.Utilities.IO;
using System.IO;
using System.Net;

namespace CAdESLib.Service
{
    /// <summary>
    /// Implementation of HTTPDataLoader using HttpClient.
    /// </summary>
    /// <remarks>
    /// Implementation of HTTPDataLoader using HttpClient. More flexible for HTTPS without having to add the certificate to
    /// the JVM TrustStore.
    /// </remarks>
    public class NetHttpDataLoader : IHTTPDataLoader
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        public string ContentType { get; set; }
        public string Accept { get; set; }
        public int TimeOut { get; set; }

        public NetHttpDataLoader()
        {
            TimeOut = 500;
        }

        public Stream Get(string URL)
        {
            try
            {
                logger.Info("Fetching data from url " + URL);

                var request = (HttpWebRequest)WebRequest.Create(URL);
                var response = (HttpWebResponse)request.GetResponse();

                if (response.StatusCode == HttpStatusCode.OK)
                {
                    Stream dataStream = response.GetResponseStream();
                    return dataStream;
                }
                else
                {
                    return new MemoryStream(new byte[0]);
                }
            }
            catch(WebException ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
            catch (IOException ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
        }

        public Stream Post(string URL, Stream content)
        {
            try
            {
                logger.Info("Post data to url " + URL);

                byte[] data = Streams.ReadAll(content);

                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URL);
                request.Timeout = TimeOut;
                request.Method = "POST";
                request.ContentLength = data.Length;

                if (ContentType != null)
                {
                    request.ContentType = ContentType;
                }

                if (Accept != null)
                {
                    request.Accept = Accept;
                }

                Stream dataStream = request.GetRequestStream();
                dataStream.Write(data, 0, data.Length);
                dataStream.Close();

                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                dataStream = response.GetResponseStream();

                return dataStream;
            }
            catch (WebException ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
            catch (IOException ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
        }
    }
}
