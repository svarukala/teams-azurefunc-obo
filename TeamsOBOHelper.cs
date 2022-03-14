using System;
using System.IO;
using System.Threading.Tasks;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Teams.Apps.HelperFunctions
{
    public static class TeamsOBOHelper
    {
        [FunctionName("TeamsOBOHelper")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("TeamsOBOHelper function processed a request.");

            string tenantId = Environment.GetEnvironmentVariable("TenantId");
            string clientId = Environment.GetEnvironmentVariable("ClientId");
            string clientSecret = Environment.GetEnvironmentVariable("ClientSecret");
            string[] downstreamApiScopes = { "https://graph.microsoft.com/.default" };
            string[] downstreamApiScopesForSPO = { "https://m365x229910.sharepoint.com/.default" };

            try
            {
                if (string.IsNullOrEmpty(tenantId) ||
                string.IsNullOrEmpty(tenantId) ||
                string.IsNullOrEmpty(tenantId))
                {
                    throw new Exception("Configuration values are missing.");
                }

                string authority = $"https://login.microsoftonline.com/{tenantId}";
                string issuer = $"https://sts.windows.net/{tenantId}/";
                string audience = $"api://{clientId}";

                var app = ConfidentialClientApplicationBuilder.Create(clientId)
                   .WithAuthority(authority)
                   .WithClientSecret(clientSecret)
                   .Build();

                var headers = req.Headers;
                var token = string.Empty;
                var tokenFor = string.Empty;
                token = req.Query["ssoToken"];
                tokenFor = req.Query["tokenFor"];
                log.LogInformation("Here is the id token: "+ token);
                log.LogInformation("Here is the token for: "+ tokenFor);
                /*
                //Use this for POST
                if (headers.TryGetValue("Authorization", out var authHeader))
                {
                    if (authHeader[0].StartsWith("Bearer "))
                    {
                        token = authHeader[0].Substring(7, authHeader[0].Length - 7);
                    }
                    else
                    {
                        return new UnauthorizedResult();
                    }
                }
                */
                var configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
                    issuer + "/.well-known/openid-configuration",
                    new OpenIdConnectConfigurationRetriever(),
                    new HttpDocumentRetriever());

                bool validatedToken = await ValidateToken(token, issuer, audience, configurationManager);

                if (!validatedToken)
                {
                    throw new Exception("Token validation failed.");
                }
                
                UserAssertion userAssertion = new UserAssertion(token);
                
                AuthenticationResult result = await app.AcquireTokenOnBehalfOf(tokenFor=="spo" ? downstreamApiScopesForSPO : downstreamApiScopes, userAssertion).ExecuteAsync();

                string accessToken = result.AccessToken;
                if (accessToken == null)
                {
                    log.LogInformation("Failed to acquire Access token");
                    throw new Exception("Access Token could not be acquired.");
                }

                var myObj = new { access_token = accessToken };
                var jsonToReturn = JsonConvert.SerializeObject(myObj);
                return new OkObjectResult(jsonToReturn);
            }
            catch (Exception ex)
            {
                return new BadRequestObjectResult(ex.Message);
            }
        }

        private static async Task<bool> ValidateToken(
            string token,
            string issuer,
            string audience,
            IConfigurationManager<OpenIdConnectConfiguration> configurationManager)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentNullException(nameof(token));
            if (string.IsNullOrEmpty(issuer)) throw new ArgumentNullException(nameof(issuer));

            var discoveryDocument = await configurationManager.GetConfigurationAsync(default(CancellationToken));
            var signingKeys = discoveryDocument.SigningKeys;

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = signingKeys,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(2),
            };

            try
            {
                new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out var rawValidatedToken);
                return true;
            }
            catch (SecurityTokenValidationException)
            {
                return false;
            }
        }

        /*
        [FunctionName("TeamsOBOHelper")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);
        }
        */
    }
}
