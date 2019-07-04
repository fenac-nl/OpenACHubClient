using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Model
{
    public enum ScanType
    {
        ValidCertificateValidJwt,
        NoCertificateValidJwt,
        ValidCertificateNoJwt,
        ValidCertificateNoSignatureJwt,
        ValidCertificateInvalidSignatureJwt,
        ValidCertificateInvalidSigningAlgorithMJwt,
        ValidCertificateExpiredJwt
    }
}
