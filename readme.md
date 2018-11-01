I came across an interesting case recently, where my customer was keen to know: as part of the authentication flow, WIF can be configured to eliminate passing the wctx parameter.

In general, the WIF module helps pass the wctx parameter with a value of rm=0&id=passive&ru=%2f. For some reason, it was a security vulnerability situation for my customer. So, was asking us to research if WIF can be configured to eliminate passing the wctx parameter.


# WIF redirection example
HeaderName="Location", HeaderValue="https://adfs.contoso.com/adfs/ls/?wa=wsignin1.0&wtrealm=https%3a%2f%2faadconnect.contoso.com%2fMVC-sample-wctx-research%2f&**wctx_=rm%3d0%26id%3dpassive%26ru%3d%252fMVC-sample-wctx-research%252f_**&wct=2018-06-01T19%3a55%3a12Z", Replace="true"

# OWIN WS-Federation redirection example
HeaderName="Location", HeaderValue="https://adfs.contoso.com/adfs/ls/?wtrealm=https%3A%2F%2Fwin10.contoso.com%2FOWINbased.MVCapp%2F&**wctx_=WsFedOwinState%3D4k4IljfUNfFFrKtegOeKW4kULHFnT6vaAPI8Dphcf8jvPMZeBKRg7kfd1S60yIebBOkrD3TIRcg2_gi-OXFmntq89AXg7I4zXBkPKCV0n_k5CAQBxskZ5HtCJIdA0cN0IhOii04pWwaqCVtoh7geNA_**&wa=wsignin1.0", Replace="true"


## Regarding "wctx" [WIF perspective]
As per the blog [https://blogs.technet.microsoft.com/askpfeplat/2014/11/02/adfs-deep-dive-comparing-ws-fed-saml-and-oauth/](https://blogs.technet.microsoft.com/askpfeplat/2014/11/02/adfs-deep-dive-comparing-ws-fed-saml-and-oauth/), "wctx" holds some session data that the application wants sent back to it after the user authenticates.
 
As per the documentation of WS-Federation ["CreateSignInRequesst"](https://msdn.microsoft.com/en-us/library/system.identitymodel.services.wsfederationauthenticationmodule.createsigninrequest(v=vs.110).aspx) API, the parameters passed to the method are used to create the wctx message parameter. This is a string with the following format: ru=returnUrl&cx=SignInContext&rm=rememberMeSet&id=uniqueId.
	* The ru value is set to the value of the returnUrl parameter passed in to the method and it specifies the URL that the module should direct the browser to following successful authentication. This is the only value stored in the wctx string that is used by the WSFAM. The module calls the GetReturnUrlFromResponse method to extract this value from the wctx parameter when processing a WS-Federation sign-in response. It should not be confused with the wreply message parameter, which is specified by the Reply property and which provides the address at the RP to which the security token service (STS) should direct its response. 
	* The cx parameter is set to the value of the SignInContext property. This property is exposed to enable you to set any application-defined context that should be stored in the wctx string; however, WSFAM does not expose a method to extract this value in the response. If the value is needed by your application, you must provide the code to parse the wctx string and read this value when processing the response. You might accomplish this by overriding the GetReturnUrlFromResponse method.
	* Neither the rm value, which is set to the value of the rememberMeSet parameter, nor the id parameter, which is set to the value of the uniqueId parameter are used by WSFAM. These can be set to any value.
 
As per the System.IdentityModel.Services source code, "wctx" is initialized by the following code.

```
        private void Initialize()
        {
            if ( _wctx == null )
            {
                StringBuilder strb = new StringBuilder( 128 );
                strb.Append( RememberMeKey );
                strb.Append( '=' );
                strb.Append( _rememberMe ? '1' : '0' );
                strb.Append( '&' );
                strb.Append( ControlIdKey );
                strb.Append( '=' );
                strb.Append( HttpUtility.UrlEncode( _controlId ) );
                if ( !String.IsNullOrEmpty( _signInContext ) )
                {
                    strb.Append( '&' );
                    strb.Append( SignInContextKey );
                    strb.Append( '=' );
                    strb.Append( HttpUtility.UrlEncode( _signInContext ) );
                }
                if ( !String.IsNullOrEmpty( _returnUrl ) )
                {
                    strb.Append( '&' );
                    strb.Append( ReturnUrlKey );
                    strb.Append( '=' );
                    strb.Append( HttpUtility.UrlEncode( _returnUrl ) );
                }
                _wctx = strb.ToString();
            }
```
So, "wctx" is constructed in plain text.


## Regarding "wctx" [Owin perspective]
For Owin WsFederation, we have the source code in [AspNetKatana repo](https://github.com/aspnet/AspNetKatana/blob/dev/src/Microsoft.Owin.Security.WsFederation/WsFederationAuthenticationHandler.cs).

``` 
        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return;
            }
 
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (challenge == null)
            {
                return;
            }
 
            if (_configuration == null)
            {
                _configuration = await Options.ConfigurationManager.GetConfigurationAsync(Context.Request.CallCancelled);
            }
 
            string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;
 
            string currentUri =
                baseUri +
                Request.Path +
                Request.QueryString;
 
            // Save the original challenge URI so we can redirect back to it when we're done.
            AuthenticationProperties properties = challenge.Properties;
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = currentUri;
            }
 
            WsFederationMessage wsFederationMessage = new WsFederationMessage()
            {
                IssuerAddress = _configuration.TokenEndpoint ?? string.Empty,
                Wtrealm = Options.Wtrealm,
                Wctx = WsFederationAuthenticationDefaults.WctxKey + "=" + Uri.EscapeDataString(Options.StateDataFormat.Protect(properties)),
                Wa = WsFederationConstants.WsFederationActions.SignIn,
            };
 
            if (!string.IsNullOrWhiteSpace(Options.Wreply))
            {
                wsFederationMessage.Wreply = Options.Wreply;
            }
 
            var notification = new RedirectToIdentityProviderNotification<WsFederationMessage, WsFederationAuthenticationOptions>(Context, Options)
            {
                ProtocolMessage = wsFederationMessage
            };
            await Options.Notifications.RedirectToIdentityProvider(notification);
 
            if (!notification.HandledResponse)
            {
                string redirectUri = notification.ProtocolMessage.CreateSignInUrl();
                if (!Uri.IsWellFormedUriString(redirectUri, UriKind.Absolute))
                {
                    _logger.WriteWarning("The sign-in redirect URI is malformed: " + redirectUri);
                }
                Response.Redirect(redirectUri);
            }
        }
```
 
### Protect API
```
        public string Protect(TData data)
        {
            byte[] userData = _serializer.Serialize(data);
            byte[] protectedData = _protector.Protect(userData);
            string protectedText = _encoder.Encode(protectedData);
            return protectedText;
        }

```

### Encode API
```
	namespace Microsoft.Owin.Security.DataHandler.Encoder
	{
	    public class Base64TextEncoder : ITextEncoder
	    {
	        public string Encode(byte[] data)
	        {
	            return Convert.ToBase64String(data);
	        }
```


# Is it possible to override "wctx" in System.IdentityModel?

The answer is "yes". 

The **wctx** can be used as a cross site scripting defense.  A value is added in a cookie that matches a value in the wctx, and the wctx is protected. On the client (browser), the wctx could be modified as the TLS is terminated. 
If you are concerned (as per org policy), then use the extensibility to protect the wctx.

1) 
Create a custom library with a class, which overrides the event **WSFederationAuthenticationModule:: OnRedirectingToIdentityProvider**.

``` 
using System;
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
```
 
2)
Later, add the custom dll reference to your web project.
 
3)
Modify web.config to read the custom module, instead of the original module WSFederationAuthenticationModule.

<pre> 
  &lt;system.webServer&gt;
..
..
    &lt;modules&gt;
      &lt;remove name="FormsAuthentication" /&gt;
              &lt;!--add name="WSFederationAuthenticationModule" type="System.IdentityModel.Services.WSFederationAuthenticationModule, System.IdentityModel.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" preCondition="managedHandler" /--&gt;
              &lt;add name="CustomFedAuthModule" type="CustomHttpModel.CustomFedAuthModule, CustomHttpModel" preCondition="managedHandler" /&gt;
              &lt;add name="SessionAuthenticationModule" type="System.IdentityModel.Services.SessionAuthenticationModule, System.IdentityModel.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" preCondition="managedHandler" /&gt;
    &lt;/modules&gt;
</pre>


I believe with this we have full control on the "wctx" parameter construction. It can be modified as per own custom rule in .NET (via custom code). Feel free to clone the whole sample, and play around. (Note: It is a VS 2012 solution, but can be opened in any)



I hope this helps.


 