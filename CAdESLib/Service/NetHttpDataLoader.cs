using LdapForNet;
using NLog;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Linq;
using System.Net;
using static LdapForNet.Native.Native;

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

        private const string LdapScheme = "ldap";

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
                logger.Trace("Fetching data from url " + URL);

                var uri = new Uri(URL);

                if (uri.Scheme.StartsWith(LdapScheme, StringComparison.OrdinalIgnoreCase))
                {
                    var arr = uri.Query.Split("?");
                    var attributes = arr[1].Split(",");
                    var scope = arr[2] ?? "base";
                    var filter = arr[3];
                    var dn = uri.LocalPath.TrimStart('/');

                    using var cn = new LdapConnection();
                    if (string.IsNullOrEmpty(uri.Host))
                    {
                        cn.Connect();
                    }
                    else
                    {
                        cn.Connect(uri.Host, uri.Port);
                    }

                    cn.Bind();

                    var results = cn.Search(dn, filter, attributes, GetSearchScope(scope));
                    var result = results.FirstOrDefault();
                    var a = result.DirectoryAttributes[attributes[0]];
                    var c = a.GetValue<byte[]>();

                    return new MemoryStream(c);
                }
                else
                {
                    var request = (HttpWebRequest)WebRequest.Create(URL);
                    request.Timeout = TimeOut;
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
            }
            catch (Exception ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
        }

        public Stream Post(string URL, Stream content)
        {
            try
            {
                logger.Trace("Post data to url " + URL);

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
            catch (Exception ex)
            {
                logger.Error(ex);
                throw new CannotFetchDataException(ex, URL);
            }
        }

        private static LdapSearchScope GetSearchScope(string val) => (val.ToLower()) switch
        {
            "base" => LdapSearchScope.LDAP_SCOPE_BASE,
            "one" => LdapSearchScope.LDAP_SCOPE_ONE,
            "sub" => LdapSearchScope.LDAP_SCOPE_SUB,
            _ => LdapSearchScope.LDAP_SCOPE_BASE,
        };
    }
}
