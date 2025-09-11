using CAdESLib.Helpers;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using System;
using System.Linq;

namespace CAdESLib.Document.Validation
{
    public class StatusSource
    {
        private BasicOcspResp? basicOcspResp;
        private X509Crl? x509Crl;


        public StatusSource() { }

        public StatusSource(BasicOcspResp resp)
        {
            this.basicOcspResp = resp;
        }

        public StatusSource(X509Crl crl)
        {
            this.x509Crl = crl;
        }

        public static StatusSource GetNotAvailableStatus(DateTime startDate, DateTime endDate)
        {
            var result = new StatusSource();
            result.NotAvailableAtTime = startDate;
            return result;
        }

        public DateTime? NotAvailableAtTime { get; private set; }

        public object? Source => this.basicOcspResp ?? (object?)this.x509Crl;

        public BasicOcspResp? Resp => this.basicOcspResp;

        public X509Crl? Crl => this.x509Crl;

        public DateTime? ThisUpdate => Resp?.Responses.First().ThisUpdate ?? Crl?.ThisUpdate;

        public DateTime? NextUpdate => Resp?.Responses.First().NextUpdate?.Value ?? Crl?.NextUpdate?.Value;

        public bool IsValidForTime(DateTime startDate, DateTime endDate) =>
            this.Crl is not null && this.Crl.IsValid(startDate, endDate) ||
            this.Resp is not null && this.Resp.IsValid(startDate, endDate) ||
            this.NotAvailableAtTime is not null && this.NotAvailableAtTime.Value.CompareTo(startDate) >= 0;

        public override string ToString()
        {
            return $"StatusSource: {Source?.GetType().ToString() ?? "none"} {ThisUpdate}-{NextUpdate}";
        }
    }
}

