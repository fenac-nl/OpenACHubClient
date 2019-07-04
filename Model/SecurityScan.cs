using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Model
{
    public class SecurityScan
    {
        public ScanType Type { get; set; }
        public string Description { get; set; } = "";
        public bool UseCertificate { get; set; } = true;
        public int ExpectedResponse { get; set; } = 201;
    }
}
