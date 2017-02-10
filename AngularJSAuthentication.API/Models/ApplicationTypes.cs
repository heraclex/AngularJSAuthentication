using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AngularJSAuthentication.API.Models
{
    public enum ApplicationTypes
    {
        /*In our case I’ve identified clients to two types (JavaScript – Nonconfidential) and (Native-Confidential) 
         * which means that for confidential clients  we can store the client secret in confidential way (valid for desktop apps, mobile apps, server side web apps) 
         * so any request coming from this client asking for access token should include the client id and secret.*/
        JavaScript = 0,
        NativeConfidential = 1
    };
}