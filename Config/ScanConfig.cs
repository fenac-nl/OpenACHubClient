using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Config
{
    public class ScanConfig
    {
        public bool ValidCertificateValidJwt { get; set; } = true;
        public bool NoCertificateValidJwt { get; set; } = true;
        public bool ValidCertificateNoJwt { get; set; } = true;
        public bool ValidCertificateNoSignatureJwt { get; set; } = true;
        public bool ValidCertificateInvalidSignatureJwt { get; set; } = true;
        public bool ValidCertificateInvalidSigningAlgorithMJwt { get; set; } = true;
        public bool ValidCertificateExpiredJwt { get; set; } = true;
    }
}
