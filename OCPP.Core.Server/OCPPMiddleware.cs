using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using OCPP.Core.Database;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace OCPP.Core.Server
{
    public partial class OCPPMiddleware
    {
        // Supported OCPP protocols (in order)
        private const string PROTOCOL_OCPP_16 = "ocpp1.6";
        private const string PROTOCOL_OCPP_20 = "ocpp2.0";
        private static readonly string[] SUPPORTED_PROTOCOLS = { PROTOCOL_OCPP_20, PROTOCOL_OCPP_16 /*, "ocpp1.5" */};
        private static readonly string[] SUPPORTED_INITIATE_OPERATIONS = { OcppInitiateOperations.RESET, OcppInitiateOperations.UNLOCK_CONNECTOR };

        // RegExp for splitting ocpp message parts
        // ^\[\s*(\d)\s*,\s*\"([^"]*)\"\s*,(?:\s*\"(\w*)\"\s*,)?\s*(.*)\s*\]$
        // Third block is optional, because responses don't have an action
        private const string MESSAGE_REG_EXP = "^\\[\\s*(\\d)\\s*,\\s*\"([^\"]*)\"\\s*,(?:\\s*\"(\\w*)\"\\s*,)?\\s*(.*)\\s*\\]$";

        private readonly RequestDelegate _next;
        private readonly ILoggerFactory _logFactory;
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        // Dictionary with status objects for each charge point
        private static Dictionary<string, ChargePointStatus> _chargePointStatusDict = new Dictionary<string, ChargePointStatus>();

        // Dictionary for processing asynchronous API calls
        private Dictionary<string, OCPPMessage> _requestQueue = new Dictionary<string, OCPPMessage>();

        public OCPPMiddleware(RequestDelegate next, ILoggerFactory logFactory, IConfiguration configuration)
        {
            _next = next;
            _logFactory = logFactory;
            _configuration = configuration;
            _logger = logFactory.CreateLogger("OCPPMiddleware");
        }

        public async Task Invoke(HttpContext context, OCPPCoreContext dbContext)
        {
            _logger.LogTrace("OCPPMiddleware => Websocket request: Path='{0}'", context.Request.Path);

            if (context.Request.Path.StartsWithSegments("/ocpp/operations"))
            {
                await ProcessInitiateOperationRequest(context, dbContext);
            }
            else if (context.Request.Path.StartsWithSegments("/ocpp"))
            {
                await ProcessReceiveOperationRequest(context, dbContext);
            }
            else if (context.Request.Path.StartsWithSegments("/chargepoints"))
            {
                await ProcessChargePointRequest(context, dbContext);
            }
            else if (context.Request.Path.Equals("/"))
            {
                await ProcessRequest(context);
            }
            else
            {
                ProcessInvalidRequest(context);
            }
        }

        private async Task ProcessReceiveOperationRequest(HttpContext context, OCPPCoreContext dbContext)
        {
            string chargepointIdentifier = GetChargePointIdentifierFromRequest(context);
            _logger.LogInformation("OCPPMiddleware => Connection request with chargepoint identifier = '{0}'", chargepointIdentifier);

            // Known chargepoint?
            if (string.IsNullOrWhiteSpace(chargepointIdentifier))
            {
                // no websocket request => failure
                _logger.LogWarning("OCPPMiddleware => FAILURE: Found no chargepoint identifier");
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return;
            }

            ChargePoint chargePoint = dbContext.Find<ChargePoint>(chargepointIdentifier);

            if (chargePoint == null)
            {
                _logger.LogWarning("OCPPMiddleware => FAILURE: Found no chargepoint with identifier={0}", chargepointIdentifier);
                context.Response.StatusCode = (int)HttpStatusCode.PreconditionFailed;
                return;
            }

            _logger.LogInformation("OCPPMiddleware => SUCCESS: Found chargepoint with identifier={0}", chargePoint.ChargePointId);

            bool useBasicAuthorization = _configuration.GetValue<bool>("UseBasicAuthorization");

            if (useBasicAuthorization && !string.IsNullOrWhiteSpace(chargePoint.Username))
            {
                var isUserAuthorized = IsUserAuthorized(context, chargePoint);

                if (!isUserAuthorized)
                {
                    context.Response.Headers.Append("WWW-Authenticate", "Basic realm=\"OCPP.Core\"");
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return;
                }
            }

            bool useClientCertAuthorization = _configuration.GetValue<bool>("UseClientCertAuthorization");

            if (useClientCertAuthorization && !string.IsNullOrWhiteSpace(chargePoint.ClientCertThumb))
            {
                bool isClientCertAuthorized = IsClientCertAuthorized(context, chargePoint);

                if (!isClientCertAuthorized)
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return;
                }
            }

            // Store chargepoint data
            ChargePointStatus chargePointStatus = new(chargePoint);

            if (!context.WebSockets.IsWebSocketRequest)
            {
                // no websocket request => failure
                _logger.LogWarning("OCPPMiddleware => Non-Websocket request");
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return;
            }

            // Match supported sub protocols
            string subProtocol = GetProtocol(context, chargepointIdentifier);

            if (string.IsNullOrEmpty(subProtocol))
            {
                return;
            }

            chargePointStatus.Protocol = subProtocol;

            bool statusSuccess = false;
            try
            {
                _logger.LogTrace("OCPPMiddleware => Store/Update status object");
                statusSuccess = AddChargePointStatus(chargepointIdentifier, chargePointStatus);
            }
            catch (Exception exp)
            {
                _logger.LogError(exp, "OCPPMiddleware => Error storing status object in dictionary => refuse connection");
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            }

            if (statusSuccess)
            {
                // Handle socket communication
                _logger.LogTrace("OCPPMiddleware => Waiting for message...");

                using (WebSocket webSocket = await context.WebSockets.AcceptWebSocketAsync(subProtocol))
                {
                    _logger.LogTrace("OCPPMiddleware => WebSocket connection with charge point '{0}'", chargepointIdentifier);
                    chargePointStatus.WebSocket = webSocket;

                    if (subProtocol == PROTOCOL_OCPP_20)
                    {
                        // OCPP V2.0
                        await Receive20(chargePointStatus, context, dbContext);
                    }
                    else
                    {
                        // OCPP V1.6
                        await Receive16(chargePointStatus, context, dbContext);
                    }
                }
            }
        }

        private static bool AddChargePointStatus(string chargepointIdentifier, ChargePointStatus chargePointStatus)
        {
            bool statusSuccess;
            lock (_chargePointStatusDict)
            {
                // Check if this chargepoint already/still hat a status object
                if (_chargePointStatusDict.ContainsKey(chargepointIdentifier))
                {
                    // exists => check status
                    if (_chargePointStatusDict[chargepointIdentifier].WebSocket.State != WebSocketState.Open)
                    {
                        // Closed or aborted => remove
                        _chargePointStatusDict.Remove(chargepointIdentifier);
                    }
                }

                _chargePointStatusDict.Add(chargepointIdentifier, chargePointStatus);
                statusSuccess = true;
            }

            return statusSuccess;
        }

        private void ProcessInvalidRequest(HttpContext context)
        {
            _logger.LogWarning("OCPPMiddleware => Bad path request");
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
        }

        private async Task ProcessRequest(HttpContext context)
        {
            try
            {
                bool showIndexInfo = _configuration.GetValue<bool>("ShowIndexInfo");
                if (showIndexInfo)
                {
                    _logger.LogTrace("OCPPMiddleware => Index status page");

                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync(string.Format("Running...\r\n\r\n{0} chargepoints connected", _chargePointStatusDict.Values.Count));
                }
                else
                {
                    _logger.LogInformation("OCPPMiddleware => Root path with deactivated index page");
                    context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                }
            }
            catch (Exception exp)
            {
                _logger.LogError(exp, "OCPPMiddleware => Error: {0}", exp.Message);
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            }
        }

        private string GetProtocol(HttpContext context, string chargepointIdentifier)
        {
            string subProtocol = null;

            foreach (string supportedProtocol in SUPPORTED_PROTOCOLS)
            {
                if (context.WebSockets.WebSocketRequestedProtocols.Contains(supportedProtocol))
                {
                    subProtocol = supportedProtocol;
                    break;
                }
            }
            if (string.IsNullOrEmpty(subProtocol))
            {
                // Not matching protocol! => failure
                string protocols = string.Empty;
                foreach (string p in context.WebSockets.WebSocketRequestedProtocols)
                {
                    if (string.IsNullOrEmpty(protocols)) protocols += ",";
                    protocols += p;
                }
                _logger.LogWarning("OCPPMiddleware => No supported sub-protocol in '{0}' from charge station '{1}'", protocols, chargepointIdentifier);
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            }

            return subProtocol;
        }

        private async Task ProcessInitiateOperationRequest(HttpContext context, OCPPCoreContext dbContext)
        {
            bool isAuthorized = IsApiRequestAuthorized(context);

            if (!isAuthorized)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return;
            }

            // format: /API/<command>[/chargepointId]
            string[] urlParts = context.Request.Path.Value.Split('/');

            if (urlParts.Length < 4)
            {
                return;
            }

            string operation = urlParts[3];
            string urlChargePointId = (urlParts.Length >= 5) ? urlParts[4] : null;
            _logger.LogTrace("OCPPMiddleware => cmd='{0}' / id='{1}' / FullPath='{2}')", operation, urlChargePointId, context.Request.Path.Value);

            if (!SUPPORTED_INITIATE_OPERATIONS.Contains(operation))
            {
                // Unknown operation
                _logger.LogWarning("OCPPMiddleware => action/function: {0}", operation);
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
            }

            if (string.IsNullOrEmpty(urlChargePointId))
            {
                _logger.LogError("OCPPMiddleware Initiate Operation => Missing chargepoint ID");
                context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                return;
            }

            ChargePointStatus status = null;
            if (!_chargePointStatusDict.TryGetValue(urlChargePointId, out status))
            {
                // Chargepoint offline
                _logger.LogError("OCPPMiddleware Initiate Operation => Chargepoint offline: {0}", urlChargePointId);
                context.Response.StatusCode = (int)HttpStatusCode.NotFound;
                return;
            }

            if (operation == OcppInitiateOperations.RESET)
            {
                try
                {
                    // Send message to chargepoint
                    if (status.Protocol == PROTOCOL_OCPP_20)
                    {
                        // OCPP V2.0
                        await Reset20(status, context, dbContext);
                    }
                    else
                    {
                        // OCPP V1.6
                        await Reset16(status, context, dbContext);
                    }
                }
                catch (Exception exp)
                {
                    _logger.LogError(exp, "OCPPMiddleware SoftReset => Error: {0}", exp.Message);
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                }
            }

            if (operation == OcppInitiateOperations.UNLOCK_CONNECTOR)
            {
                try
                {
                    // Send message to chargepoint
                    if (status.Protocol == PROTOCOL_OCPP_20)
                    {
                        // OCPP V2.0
                        await UnlockConnector20(status, context, dbContext);
                    }
                    else
                    {
                        // OCPP V1.6
                        await UnlockConnector16(status, context, dbContext);
                    }
                }
                catch (Exception exp)
                {
                    _logger.LogError(exp, "OCPPMiddleware UnlockConnector => Error: {0}", exp.Message);
                    context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                }
            }
        }

        private async Task ProcessChargePointRequest(HttpContext context, OCPPCoreContext dbContext)
        {
            bool isAuthorized = IsApiRequestAuthorized(context);

            if (!isAuthorized)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                return;
            }

            // format: /API/<command>[/chargepointId]
            string[] urlParts = context.Request.Path.Value.Split('/');

            //string cmd = urlParts[2];
            //string urlChargePointId = (urlParts.Length >= 4) ? urlParts[3] : null;
            //_logger.LogTrace("OCPPMiddleware => cmd='{0}' / id='{1}' / FullPath='{2}')", cmd, urlChargePointId, context.Request.Path.Value);

            try
            {
                List<ChargePointStatus> statusList = (from ChargePointStatus status in _chargePointStatusDict.Values select status).ToList();
                string jsonStatus = JsonConvert.SerializeObject(statusList);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(jsonStatus);
            }
            catch (Exception exp)
            {
                _logger.LogError(exp, "OCPPMiddleware => Error: {0}", exp.Message);
                context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
            }
        }

        private bool IsApiRequestAuthorized(HttpContext context)
        {
            // Check authentication (X-API-Key)
            string apiKeyConfig = _configuration.GetValue<string>("ApiKey");

            if (string.IsNullOrWhiteSpace(apiKeyConfig))
            {
                // No API-Key configured => no authenticatiuon
                _logger.LogWarning("OCPPMiddleware => No X-API-Key configured!");
                return false;
            }

            // ApiKey specified => check request
            string apiKeyCaller = context.Request.Headers["X-API-Key"].FirstOrDefault();

            if (apiKeyConfig != apiKeyCaller)
            {
                // API-Key does NOT matches => authentication failure!!!
                _logger.LogWarning("OCPPMiddleware => Failure: Wrong X-API-Key! Caller='{0}'", apiKeyCaller);
                return false;
            }

            // API-Key matches
            _logger.LogInformation("OCPPMiddleware => Success: X-API-Key matches");
            return true;
        }

        private static string GetChargePointIdentifierFromRequest(HttpContext context)
        {
            string chargepointIdentifier;
            string[] parts = context.Request.Path.Value.Split('/');
            if (string.IsNullOrWhiteSpace(parts[parts.Length - 1]))
            {
                // (Last part - 1) is chargepoint identifier
                chargepointIdentifier = parts[parts.Length - 2];
            }
            else
            {
                // Last part is chargepoint identifier
                chargepointIdentifier = parts[parts.Length - 1];
            }

            return chargepointIdentifier;
        }

        private bool IsClientCertAuthorized(HttpContext context, ChargePoint chargePoint)
        {
            // Chargepoint MUST send basic authentication header

            bool certAuthSuccess = false;
            X509Certificate2 clientCert = context.Connection.ClientCertificate;
            if (clientCert != null)
            {
                if (clientCert.Thumbprint.Equals(chargePoint.ClientCertThumb, StringComparison.InvariantCultureIgnoreCase))
                {
                    // Authentication match => OK
                    _logger.LogInformation("OCPPMiddleware => SUCCESS: Certificate authentication for chargepoint '{0}' match", chargePoint.ChargePointId);
                    certAuthSuccess = true;
                }
                else
                {
                    // Authentication does NOT match => Failure
                    _logger.LogWarning("OCPPMiddleware => FAILURE: Certificate authentication for chargepoint '{0}' does NOT match", chargePoint.ChargePointId);
                }
            }
            if (certAuthSuccess == false)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }

            return certAuthSuccess;
        }

        private bool IsUserAuthorized(HttpContext context, ChargePoint chargePoint)
        {
            // Chargepoint MUST send basic authentication header

            bool basicAuthSuccess = false;

            string authHeader = context.Request.Headers.Authorization;
            if (!string.IsNullOrEmpty(authHeader))
            {
                string[] credentials = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(authHeader.Substring(6))).Split(':');
                string username = credentials[0].Trim();
                string password = credentials[1].Trim();

                if (credentials.Length == 2 && chargePoint.ChargePointId == username && chargePoint.Password == password)
                {
                    // Authentication match => OK
                    _logger.LogInformation("OCPPMiddleware => SUCCESS: Basic authentication for chargepoint '{0}' match", chargePoint.ChargePointId);
                    basicAuthSuccess = true;
                }
                else
                {
                    // Authentication does NOT match => Failure
                    _logger.LogWarning("OCPPMiddleware => FAILURE: Basic authentication for chargepoint '{0}' does NOT match", chargePoint.ChargePointId);
                }
            }
            if (basicAuthSuccess == false)
            {
                context.Response.Headers.Append("WWW-Authenticate", "Basic realm=\"OCPP.Core\"");
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            }

            return basicAuthSuccess;
        }
    }

    public static class OCPPMiddlewareExtensions
    {
        public static IApplicationBuilder UseOCPPMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<OCPPMiddleware>();
        }
    }

    public static class OcppInitiateOperations
    {
        public const string RESET = "Reset";
        public const string UNLOCK_CONNECTOR = "UnlockConnector";
    }
}
