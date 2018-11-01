using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Services;

namespace CustomHttpModel
{
    public class CustomFedAuthModule : WSFederationAuthenticationModule
    {
        protected override void OnRedirectingToIdentityProvider(RedirectingToIdentityProviderEventArgs e)
        {
            // Read "wctx" parameter by reading the value of e.SignInRequestMessage.Context. It's a get/set property.
            
            // If you want to omit wctx value, set wctx to null or empty
            //e.SignInRequestMessage.Context = null;
            //e.SignInRequestMessage.Context = string.Empty;

            // If you want to set wctx to an encoded value
            var _wctx = e.SignInRequestMessage.Context;
            e.SignInRequestMessage.Context = Encode(_wctx);

            base.OnRedirectingToIdentityProvider(e);
        }

        private string Encode(string data)
        {
            var plainTextBytes = Encoding.UTF8.GetBytes(data);
            return Convert.ToBase64String(plainTextBytes);
        }
    }
}
