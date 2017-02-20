using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using AngularJSAuthentication.API.Entities;
using AngularJSAuthentication.API.Repositories;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// Responsible for validating the “Client”, 
        /// In our case we have only one client so we’ll always return that its validated successfully
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            Client client = null;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                //Remove the comments from the below line context.SetError, and invalidate context 
                //if you want to force sending clientId/secrects once obtain access tokens. 
                context.Validated();
                //context.SetError("invalid_clientId", "ClientId should be sent.");
                return Task.FromResult<object>(null);
            }

            using (AuthRepository _repo = new AuthRepository())
            {
                client = _repo.FindClient(context.ClientId);
            }

            if (client == null)
            {
                context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
                return Task.FromResult<object>(null);
            }

            if (client.ApplicationType == Models.ApplicationTypes.NativeConfidential)
            {
                if (string.IsNullOrWhiteSpace(clientSecret))
                {
                    context.SetError("invalid_clientId", "Client secret should be sent.");
                    return Task.FromResult<object>(null);
                }
                else
                {
                    if (client.Secret != Helper.GetHash(clientSecret))
                    {
                        context.SetError("invalid_clientId", "Client secret is invalid.");
                        return Task.FromResult<object>(null);
                    }
                }
            }

            if (!client.Active)
            {
                context.SetError("invalid_clientId", "Client is inactive.");
                return Task.FromResult<object>(null);
            }

            /*
             * We are trying to get the Client id and secret from the authorization header using a basic scheme 
             * so one way to send the client_id/client_secret is to base64 encode the (client_id:client_secret) 
             * and send it in the Authorization header. 
             * The other way is to sent the client_id/client_secret as “x-www-form-urlencoded”. 
             * In my case I’m supporting the both approaches so client can set those values using any of the two available options.
             */
            context.OwinContext.Set<string>("as:clientAllowedOrigin", client.AllowedOrigin);
            context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        /// <summary>
        /// Responsible to validate the username and password sent to the authorization server’s token endpoint
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            /*
             To allow CORS on the token middleware provider we need to add the header “Access-Control-Allow-Origin” to Owin context, 
             if you forget this, generating the token will fail when you try to call it from your browser. 
             Not that this allows CORS for token middleware provider not for ASP.NET Web API which we’ll add on the next step.
             */
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            // Use the “AuthRepository” class we created earlier and call the method “FindUser” to check if the username and password are valid.
            using (AuthRepository _repo = new AuthRepository())
            {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            /*
             If the credentials are valid we’ll create “ClaimsIdentity” class and pass the authentication type to it, 
             in our case “bearer token”, then we’ll add two claims (“sub”,”role”) and those will be included in the signed token. 
             You can add different claims here but the token size will increase for sure.
             */
            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));

            var props = new AuthenticationProperties(new Dictionary<string, string>
                {
                    {
                        "as:client_id", (context.ClientId == null) ? string.Empty : context.ClientId
                    },
                    {
                        "userName", context.UserName
                    }
                });

            var ticket = new AuthenticationTicket(identity, props);

            // Now generating the token happens behind the scenes when we call “context.Validated(identity)”.
            context.Validated(ticket);
        }

        /// <summary>
        /// The request context contains all the claims stored previously for this user, we need to add logic which allows us to issue new claims or updating existing claims 
        /// and contain them into the new access token generated before sending it to the user.
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            //We are reading the client id value from the original ticket, this is the client id which get stored in 
            // the magical signed string, then we compare this client id against the client id sent with the request, 
            // if they are different we’ll reject this request because we need to make sure that the refresh token used here is bound to the same client when it was generated.
            var originalClient = context.Ticket.Properties.Dictionary["as:client_id"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            // We have the chance now to add new claims or remove existing claims, this was not achievable without refresh tokens, 
            // then we call “context.Validated(newTicket)” which will generate new access token and return it in the response body.
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            // Lastly after this method executes successfully, the flow for the code will hit method “CreateAsync” in class “SimpleRefreshTokenProvider” 
            // and a new refresh token is generated and returned in the response along with the new access token.
            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}