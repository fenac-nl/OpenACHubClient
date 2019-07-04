using System;
using System.Collections.Generic;
using System.Text;

namespace OpenACHubClient.Model.Zorgdomein
{
    public class JwtHeader
    {
        public string Alg { get; set; } = "RS256";
        public string Typ { get; set; } = "JWT";
        public string Kid { get; set; } = "Fenac-Test";
    }
}
