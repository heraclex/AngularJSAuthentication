using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using AngularJSAuthentication.API.Repositories;
using Microsoft.AspNet.Identity.EntityFramework;
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
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
        }

        /// <summary>
        /// Responsible to validate the username and password sent to the authorization server’s token endpoint
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
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
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim(ClaimTypes.Role, "user"));

            // Now generating the token happens behind the scenes when we call “context.Validated(identity)”.
            context.Validated(identity);
        }
    }
}