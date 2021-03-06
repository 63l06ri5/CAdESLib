﻿using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using CAdESLib.Document.Validation;
using BcCms = Org.BouncyCastle.Asn1.Cms;

namespace CAdESLib.Document.Signature.Extensions
{
    /// <summary>
    /// This class holds the CAdES-X signature profiles; it supports the inclusion of a combination of the unsigned
    /// attributes id-aa-ets-escTimeStamp, id-aa-ets-certCRLTimestamp, id-aa-ets-certValues, id-aa-ets-revocationValues as
    /// defined in ETSI TS 101 733 V1.8.1, clause 6.3.
    /// </summary>

    public class CAdESProfileXL : CAdESProfileX
    {
        /// <summary>
        /// Sets the type of the CAdES-X signature (Type 1 with id-aa-ets-escTimeStamp or Type 2 with
        /// id-aa-ets-certCRLTimestamp)
        /// </summary>
        /// <param>
        /// to type to set, 1 or 2
        /// </param>
        public override void SetExtendedValidationType(int extendedValidationType)
        {
            this.extendedValidationType = extendedValidationType;
        }

        private IDictionary ExtendUnsignedAttributes(IDictionary unsignedAttrs, X509Certificate signingCertificate, DateTime signingDate, ICertificateSource optionalCertificateSource)
        {
            var validationContext = CertificateVerifier.ValidateCertificate(signingCertificate, signingDate, optionalCertificateSource, null, null);

            List<X509CertificateStructure> certificateValues = new List<X509CertificateStructure>();
            List<CertificateList> crlValues = new List<CertificateList>();
            List<BasicOcspResponse> ocspValues = new List<BasicOcspResponse>();
            foreach (CertificateAndContext c in validationContext.NeededCertificates)
            {
                if (!c.Equals(signingCertificate))
                {
                    certificateValues.Add(X509CertificateStructure.GetInstance(((Asn1Sequence)Asn1Object.FromByteArray(c.Certificate.GetEncoded()))));
                }
            }
            foreach (X509Crl relatedcrl in validationContext.NeededCRL)
            {
                crlValues.Add(CertificateList.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(relatedcrl.GetEncoded())));
            }
            foreach (BasicOcspResp relatedocspresp in validationContext.NeededOCSPResp)
            {
                ocspValues.Add((BasicOcspResponse.GetInstance((Asn1Sequence)Asn1Object.FromByteArray(relatedocspresp.GetEncoded()))));
            }
            RevocationValues revocationValues = new RevocationValues(crlValues.ToArray(), ocspValues.ToArray(), null);
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsRevocationValues, new DerSet(revocationValues)));
            unsignedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsCertValues, new BcCms.Attribute(PkcsObjectIdentifiers.IdAAEtsCertValues, new DerSet(new DerSequence(certificateValues.ToArray()))));

            return unsignedAttrs;
        }

        protected internal override SignerInformation ExtendCMSSignature(CmsSignedData signedData, SignerInformation si, SignatureParameters parameters, Document originalData)
        {
            if (parameters is null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            si = base.ExtendCMSSignature(signedData, si, parameters, originalData);
            IDictionary unsignedAttrs = si.UnsignedAttributes.ToDictionary();
            CAdESSignature signature = new CAdESSignature(signedData, si.SignerID);
            DateTime signingTime = signature.SigningTime.Value;
            if (signingTime == null)
            {
                signingTime = parameters.SigningDate;
            }
            if (signingTime == null)
            {
                signingTime = DateTime.Now;
            }
            unsignedAttrs = ExtendUnsignedAttributes(unsignedAttrs, signature.SigningCertificate, signingTime, signature.CertificateSource);
            SignerInformation newsi = SignerInformation.ReplaceUnsignedAttributes(si, new BcCms.AttributeTable
                (unsignedAttrs));
            return newsi;
        }
    }
}
