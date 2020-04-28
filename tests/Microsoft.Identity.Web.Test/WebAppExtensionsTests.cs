// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web.Resource;
using Microsoft.Identity.Web.Test.Common;
using Microsoft.Identity.Web.Test.Common.TestHelpers;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using NSubstitute;
using NSubstitute.Extensions;
using Xunit;

namespace Microsoft.Identity.Web.Test
{
    public class WebAppExtensionsTests
    {
        private const string _configSectionName = "AzureAd-Custom";
        private const string _oidcScheme = "OpenIdConnect-Custom";
        private const string _cookieScheme = "Cookies-Custom";
        private IConfigurationSection _configSection;
        private readonly Action<ConfidentialClientApplicationOptions> _configureAppOptions = (options) => { };
        private readonly Action<OpenIdConnectOptions> _configureOidcOptions = (options) => {
            options.ClientId = TestConstants.ClientId;
        };
        private Action<MicrosoftIdentityOptions> _configureMsOptions = (options) => {
            options.Instance = TestConstants.AadInstance;
            options.TenantId = TestConstants.TenantIdAsGuid;
            options.ClientId = TestConstants.ClientId;
        };

        public WebAppExtensionsTests()
        {
            _configSection = GetConfigSection(_configSectionName);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void AddSignIn_WithConfigName(bool useServiceCollectionExtension)
        {
            var configMock = Substitute.For<IConfiguration>();
            configMock.Configure().GetSection(_configSectionName).Returns(_configSection);
              
            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);

            var provider = services.BuildServiceProvider();

            // Assert config bind actions added correctly
            provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);
            provider.GetRequiredService<IOptionsFactory<MicrosoftIdentityOptions>>().Create("");
            configMock.Received(3).GetSection(_configSectionName);

            AddSignIn_TestCommon(services, provider);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void AddSignIn_WithConfigActions(bool useServiceCollectionExtension)
        {
            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);

            var provider = services.BuildServiceProvider();

            // Assert configure options actions added correctly
            var configuredOidcOptions = provider.GetServices<IConfigureOptions<OpenIdConnectOptions>>().Cast<ConfigureNamedOptions<OpenIdConnectOptions>>();
            var configuredMsOptions = provider.GetServices<IConfigureOptions<MicrosoftIdentityOptions>>().Cast<ConfigureNamedOptions<MicrosoftIdentityOptions>>();

            Assert.Contains(configuredOidcOptions, o => o.Action == _configureOidcOptions);
            Assert.Contains(configuredMsOptions, o => o.Action == _configureMsOptions);

            AddSignIn_TestCommon(services, provider);
        }

        private void AddSignIn_TestCommon(IServiceCollection services, ServiceProvider provider)
        {
            // Assert correct services added           
            Assert.Contains(services, s => s.ServiceType == typeof(IConfigureOptions<OpenIdConnectOptions>));
            Assert.Contains(services, s => s.ServiceType == typeof(IConfigureOptions<MicrosoftIdentityOptions>));
            Assert.Contains(services, s => s.ServiceType == typeof(IOpenIdConnectMiddlewareDiagnostics));
            Assert.Equal(ServiceLifetime.Singleton, services.First(s => s.ServiceType == typeof(IOpenIdConnectMiddlewareDiagnostics)).Lifetime);
            Assert.Contains(services, s => s.ServiceType == typeof(IPostConfigureOptions<CookieAuthenticationOptions>));

            // Assert OIDC options added correctly
            var configuredOidcOptions = provider.GetService<IConfigureOptions<OpenIdConnectOptions>>() as ConfigureNamedOptions<OpenIdConnectOptions>;

            Assert.Equal(_oidcScheme, configuredOidcOptions.Name);

            // Assert properties set
            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            Assert.Equal(_cookieScheme, oidcOptions.SignInScheme);
            Assert.NotNull(oidcOptions.Authority);
            Assert.NotNull(oidcOptions.TokenValidationParameters.IssuerValidator);
            Assert.Equal(ClaimConstants.PreferredUserName, oidcOptions.TokenValidationParameters.NameClaimType);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task AddSignIn_WithConfigName_OnRedirectToIdentityProviderEvent(bool useServiceCollectionExtension)
        {
            var configMock = Substitute.For<IConfiguration>();
            configMock.Configure().GetSection(_configSectionName).Returns(_configSection);

            var redirectFunc = Substitute.For<Func<RedirectContext, Task>>();
            var services = new ServiceCollection()
                .Configure<OpenIdConnectOptions>(_oidcScheme, (options) => {
                    options.Events ??= new OpenIdConnectEvents();
                    options.Events.OnRedirectToIdentityProvider += redirectFunc;
                });
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);

            await AddSignIn_TestOnRedirectToIdentityProviderEvent(services, redirectFunc).ConfigureAwait(false);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task AddSignIn_WithConfigActions_OnRedirectToIdentityProviderEvent(bool useServiceCollectionExtension)
        {
            var redirectFunc = Substitute.For<Func<RedirectContext, Task>>();
            var services = new ServiceCollection()
                .Configure<OpenIdConnectOptions>(_oidcScheme, (options) => {
                    options.Events ??= new OpenIdConnectEvents();
                    options.Events.OnRedirectToIdentityProvider += redirectFunc;
                });
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);

            await AddSignIn_TestOnRedirectToIdentityProviderEvent(services, redirectFunc).ConfigureAwait(false);
        }

        private async Task AddSignIn_TestOnRedirectToIdentityProviderEvent(IServiceCollection services, Func<RedirectContext, Task> redirectFunc)
        {
            var provider = services.BuildServiceProvider();

            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            var httpContext = HttpContextUtilities.CreateHttpContext();
            var authScheme = new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme, typeof(OpenIdConnectHandler));
            var authProperties = new AuthenticationProperties();
            authProperties.Items[OidcConstants.AdditionalClaims] = "additional_claims";
            authProperties.Parameters[OpenIdConnectParameterNames.LoginHint] = "login_hint";
            authProperties.Parameters[OpenIdConnectParameterNames.DomainHint] = "domain_hint";
            var redirectContext = new RedirectContext(httpContext, authScheme, oidcOptions, authProperties)
            {
                ProtocolMessage = new OpenIdConnectMessage(),
            };

            await oidcOptions.Events.RedirectToIdentityProvider(redirectContext).ConfigureAwait(false);

            // Assert properties set, events called
            await redirectFunc.ReceivedWithAnyArgs().Invoke(Arg.Any<RedirectContext>()).ConfigureAwait(false);
            Assert.NotNull(redirectContext.ProtocolMessage.LoginHint);
            Assert.NotNull(redirectContext.ProtocolMessage.DomainHint);
            Assert.NotNull(redirectContext.ProtocolMessage.Parameters[OidcConstants.AdditionalClaims]);
        }

        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public void AddSignIn_WithConfigName_SubscribesToDiagnostics(bool useServiceCollectionExtension, bool subscribeToDiagnostics)
        {
            var configMock = Substitute.For<IConfiguration>();
            configMock.Configure().GetSection(_configSectionName).Returns(_configSection);

            var diagnosticsMock = Substitute.For<IOpenIdConnectMiddlewareDiagnostics>();

            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, subscribeToDiagnostics);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, subscribeToDiagnostics);

            AddSignIn_TestSubscribesToDiagnostics(services, diagnosticsMock, subscribeToDiagnostics);
        }

        [Theory]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public void AddSignIn_WithConfigActions_SubscribesToDiagnostics(bool useServiceCollectionExtension, bool subscribeToDiagnostics)
        {
            var diagnosticsMock = Substitute.For<IOpenIdConnectMiddlewareDiagnostics>();

            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, subscribeToDiagnostics);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, subscribeToDiagnostics);

            AddSignIn_TestSubscribesToDiagnostics(services, diagnosticsMock, subscribeToDiagnostics);
        }

        private void AddSignIn_TestSubscribesToDiagnostics(IServiceCollection services, IOpenIdConnectMiddlewareDiagnostics diagnosticsMock, bool subscribeToDiagnostics)
        {
            services.RemoveAll<IOpenIdConnectMiddlewareDiagnostics>();
            services.AddSingleton<IOpenIdConnectMiddlewareDiagnostics>((provider) => diagnosticsMock);

            var provider = services.BuildServiceProvider();

            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            // Assert subscribed to diagnostics
            if (subscribeToDiagnostics)
                diagnosticsMock.ReceivedWithAnyArgs().Subscribe(Arg.Any<OpenIdConnectEvents>());
            else
                diagnosticsMock.DidNotReceiveWithAnyArgs().Subscribe(Arg.Any<OpenIdConnectEvents>());
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task AddSignIn_WithConfigName_B2cSpecificSetup(bool useServiceCollectionExtension)
        {
            var configMock = Substitute.For<IConfiguration>();
            _configSection = GetConfigSection(_configSectionName, true);
            configMock.Configure().GetSection(_configSectionName).Returns(_configSection);

            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(configMock, _configSectionName, _oidcScheme, _cookieScheme, false);

            await AddSignIn_TestB2cSpecificSetup(services).ConfigureAwait(false);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task AddSignIn_WithConfigActions_B2cSpecificSetup(bool useServiceCollectionExtension)
        {
            _configureMsOptions = (options) => {
                options.Instance = TestConstants.AadInstance;
                options.TenantId = TestConstants.TenantIdAsGuid;
                options.ClientId = TestConstants.ClientId;
                options.SignUpSignInPolicyId = TestConstants.B2CSignUpSignInUserFlow;
                options.Domain = TestConstants.Domain;
            };

            var services = new ServiceCollection();
            services.AddDataProtection();

            if (useServiceCollectionExtension)
                services.AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);
            else
                new AuthenticationBuilder(services)
                    .AddSignIn(_configureOidcOptions, _configureMsOptions, _oidcScheme, _cookieScheme, false);

            await AddSignIn_TestB2cSpecificSetup(services).ConfigureAwait(false);
        }

        private async Task AddSignIn_TestB2cSpecificSetup(IServiceCollection services)
        {
            var provider = services.BuildServiceProvider();

            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            // Assert B2C name claim type
            Assert.Equal(ClaimConstants.Name, oidcOptions.TokenValidationParameters.NameClaimType);

            var httpContext = HttpContextUtilities.CreateHttpContext();
            var authScheme = new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme, typeof(OpenIdConnectHandler));
            var authProperties = new AuthenticationProperties();
            authProperties.Items[OidcConstants.PolicyKey] = TestConstants.B2CResetPasswordUserFlow;
            var redirectContext = new RedirectContext(httpContext, authScheme, oidcOptions, authProperties)
            {
                ProtocolMessage = new OpenIdConnectMessage() { IssuerAddress = $"IssuerAddress/{TestConstants.B2CSignUpSignInUserFlow}/" },
            };

            await oidcOptions.Events.RedirectToIdentityProvider(redirectContext).ConfigureAwait(false);

            // Assert issuer is updated to non-default user flow
            Assert.Contains(TestConstants.B2CResetPasswordUserFlow, redirectContext.ProtocolMessage.IssuerAddress);
        }

        private IConfigurationSection GetConfigSection(string configSectionName, bool includeB2cConfig = false)
        {
            var configAsDictionary = new Dictionary<string, string>()
            {
                { configSectionName, null },
                { $"{configSectionName}:Instance", TestConstants.AadInstance },
                { $"{configSectionName}:TenantId", TestConstants.TenantIdAsGuid },
                { $"{configSectionName}:ClientId", TestConstants.TenantIdAsGuid },
                { $"{configSectionName}:Domain", TestConstants.Domain },
            };

            if (includeB2cConfig)
            {
                configAsDictionary.Add($"{configSectionName}:SignUpSignInPolicyId", TestConstants.B2CSignUpSignInUserFlow);
            }

            var memoryConfigSource = new MemoryConfigurationSource { InitialData = configAsDictionary };
            var configBuilder = new ConfigurationBuilder();
            configBuilder.Add(memoryConfigSource);
            var configSection = configBuilder.Build().GetSection(configSectionName);
            return configSection;
        }

        [Fact]
        public async Task AddWebAppCallsProtectedWebApi_WithConfigName()
        {
            var configMock = Substitute.For<IConfiguration>();
            var initialScopes = new List<string>() { };
            var tokenAcquisitionMock = Substitute.For<ITokenAcquisition, ITokenAcquisitionInternal>();
            var authCodeReceivedFuncMock = Substitute.For<Func<AuthorizationCodeReceivedContext, Task>>();
            var tokenValidatedFuncMock = Substitute.For<Func<TokenValidatedContext, Task>>();
            var redirectFuncMock = Substitute.For<Func<RedirectContext, Task>>();

            var services = new ServiceCollection()
                .AddWebAppCallsProtectedWebApi(configMock, initialScopes, _configSectionName, _oidcScheme)
                .Configure<OpenIdConnectOptions>(_oidcScheme, (options) => {
                    options.Events ??= new OpenIdConnectEvents();
                    options.Events.OnAuthorizationCodeReceived += authCodeReceivedFuncMock;
                    options.Events.OnTokenValidated += tokenValidatedFuncMock;
                    options.Events.OnRedirectToIdentityProviderForSignOut += redirectFuncMock;
                });

            services.RemoveAll<ITokenAcquisition>();
            services.AddScoped<ITokenAcquisition>((provider) => tokenAcquisitionMock);

            var provider = services.BuildServiceProvider();

            // Assert config bind actions added correctly
            provider.GetRequiredService<IOptionsFactory<ConfidentialClientApplicationOptions>>().Create("");
            provider.GetRequiredService<IOptionsFactory<MicrosoftIdentityOptions>>().Create("");

            configMock.Received(2).GetSection(_configSectionName);

            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            AddWebAppCallsProtectedWebApi_TestCommon(services, provider);
            await AddWebAppCallsProtectedWebApi_TestAuthorizationCodeReceivedEvent(provider, oidcOptions, authCodeReceivedFuncMock, tokenAcquisitionMock).ConfigureAwait(false);
            await AddWebAppCallsProtectedWebApi_TestTokenValidatedEvent(oidcOptions, tokenValidatedFuncMock).ConfigureAwait(false);
            await AddWebAppCallsProtectedWebApi_TestRedirectToIdentityProviderForSignOutEvent(provider, oidcOptions, redirectFuncMock, tokenAcquisitionMock).ConfigureAwait(false);
        }

        [Fact]
        public async Task AddWebAppCallsProtectedWebApi_WithConfigActions()
        {
            var initialScopes = new List<string>() { };
            var tokenAcquisitionMock = Substitute.For<ITokenAcquisition, ITokenAcquisitionInternal>();
            var authCodeReceivedFuncMock = Substitute.For<Func<AuthorizationCodeReceivedContext, Task>>();
            var tokenValidatedFuncMock = Substitute.For<Func<TokenValidatedContext, Task>>();
            var redirectFuncMock = Substitute.For<Func<RedirectContext, Task>>();

            var services = new ServiceCollection()
                .AddWebAppCallsProtectedWebApi(initialScopes, _configureMsOptions, _configureAppOptions, _oidcScheme)
                .Configure<OpenIdConnectOptions>(_oidcScheme, (options) => {
                    options.Events ??= new OpenIdConnectEvents();
                    options.Events.OnAuthorizationCodeReceived += authCodeReceivedFuncMock;
                    options.Events.OnTokenValidated += tokenValidatedFuncMock;
                    options.Events.OnRedirectToIdentityProviderForSignOut += redirectFuncMock;
                });

            services.RemoveAll<ITokenAcquisition>();
            services.AddScoped<ITokenAcquisition>((provider) => tokenAcquisitionMock);

            var provider = services.BuildServiceProvider();

            // Assert configure options actions added correctly
            var configuredAppOptions = provider.GetServices<IConfigureOptions<ConfidentialClientApplicationOptions>>().Cast<ConfigureNamedOptions<ConfidentialClientApplicationOptions>>();
            var configuredMsOptions = provider.GetServices<IConfigureOptions<MicrosoftIdentityOptions>>().Cast<ConfigureNamedOptions<MicrosoftIdentityOptions>>();

            Assert.Contains(configuredAppOptions, o => o.Action == _configureAppOptions);
            Assert.Contains(configuredMsOptions, o => o.Action == _configureMsOptions);

            var oidcOptions = provider.GetRequiredService<IOptionsFactory<OpenIdConnectOptions>>().Create(_oidcScheme);

            AddWebAppCallsProtectedWebApi_TestCommon(services, provider);
            await AddWebAppCallsProtectedWebApi_TestAuthorizationCodeReceivedEvent(provider, oidcOptions, authCodeReceivedFuncMock, tokenAcquisitionMock).ConfigureAwait(false);
            await AddWebAppCallsProtectedWebApi_TestTokenValidatedEvent(oidcOptions, tokenValidatedFuncMock).ConfigureAwait(false);
            await AddWebAppCallsProtectedWebApi_TestRedirectToIdentityProviderForSignOutEvent(provider, oidcOptions, redirectFuncMock, tokenAcquisitionMock).ConfigureAwait(false);
        }

        private void AddWebAppCallsProtectedWebApi_TestCommon(IServiceCollection services, ServiceProvider provider)
        {
            // Assert correct services added
            Assert.Contains(services, s => s.ServiceType == typeof(IHttpContextAccessor));
            Assert.Contains(services, s => s.ServiceType == typeof(ITokenAcquisition));
            Assert.Contains(services, s => s.ServiceType == typeof(IConfigureOptions<ConfidentialClientApplicationOptions>));
            Assert.Contains(services, s => s.ServiceType == typeof(IConfigureOptions<MicrosoftIdentityOptions>));
            Assert.Contains(services, s => s.ServiceType == typeof(IConfigureOptions<OpenIdConnectOptions>));

            // Assert OIDC options added correctly
            var configuredOidcOptions = provider.GetService<IConfigureOptions<OpenIdConnectOptions>>() as ConfigureNamedOptions<OpenIdConnectOptions>;

            Assert.Equal(_oidcScheme, configuredOidcOptions.Name);
        }

        private async Task AddWebAppCallsProtectedWebApi_TestAuthorizationCodeReceivedEvent(IServiceProvider provider, OpenIdConnectOptions oidcOptions, Func<AuthorizationCodeReceivedContext, Task> authCodeReceivedFuncMock, ITokenAcquisition tokenAcquisitionMock)
        {
            var httpContext = HttpContextUtilities.CreateHttpContext();
            httpContext.RequestServices = provider;
            var authScheme = new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme, typeof(OpenIdConnectHandler));
            var authProperties = new AuthenticationProperties();
            var authCodeReceivedContext = new AuthorizationCodeReceivedContext(httpContext, authScheme, oidcOptions, authProperties);

            await oidcOptions.Events.AuthorizationCodeReceived(authCodeReceivedContext).ConfigureAwait(false);

            // Assert event called
            await authCodeReceivedFuncMock.ReceivedWithAnyArgs().Invoke(Arg.Any<AuthorizationCodeReceivedContext>()).ConfigureAwait(false);
            await ((ITokenAcquisitionInternal)tokenAcquisitionMock).ReceivedWithAnyArgs().AddAccountToCacheFromAuthorizationCodeAsync(Arg.Any<AuthorizationCodeReceivedContext>(), Arg.Any<IEnumerable<string>>()).ConfigureAwait(false);
        }

        private async Task AddWebAppCallsProtectedWebApi_TestTokenValidatedEvent(OpenIdConnectOptions oidcOptions, Func<TokenValidatedContext, Task> tokenValidatedFuncMock)
        {
            var httpContext = HttpContextUtilities.CreateHttpContext();
            httpContext.Request.Form = new FormCollection(
                new Dictionary<string, StringValues>() { { ClaimConstants.ClientInfo, Base64UrlHelpers.Encode($"{{\"uid\":\"{TestConstants.TenantIdAsGuid}\",\"utid\":\"{TestConstants.TenantIdAsGuid}\"}}") } });
            var authScheme = new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme, typeof(OpenIdConnectHandler));
            var authProperties = new AuthenticationProperties();
            var claimsPrincipal = new ClaimsPrincipal();
            var tokenValidatedContext = new TokenValidatedContext(httpContext, authScheme, oidcOptions, httpContext.User, authProperties);

            await oidcOptions.Events.TokenValidated(tokenValidatedContext).ConfigureAwait(false);

            // Assert event called, properties set
            await tokenValidatedFuncMock.ReceivedWithAnyArgs().Invoke(Arg.Any<TokenValidatedContext>()).ConfigureAwait(false);
            Assert.True(tokenValidatedContext.Principal.HasClaim(c => c.Type == ClaimConstants.Tid));
            Assert.True(tokenValidatedContext.Principal.HasClaim(c => c.Type == ClaimConstants.UniqueObjectIdentifier));
        }

        private async Task AddWebAppCallsProtectedWebApi_TestRedirectToIdentityProviderForSignOutEvent(IServiceProvider provider, OpenIdConnectOptions oidcOptions, Func<RedirectContext, Task> redirectFuncMock, ITokenAcquisition tokenAcquisitionMock)
        {
            var httpContext = HttpContextUtilities.CreateHttpContext();
            httpContext.RequestServices = provider;
            var authScheme = new AuthenticationScheme(OpenIdConnectDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme, typeof(OpenIdConnectHandler));
            var authProperties = new AuthenticationProperties();
            var redirectContext = new RedirectContext(httpContext, authScheme, oidcOptions, authProperties);

            await oidcOptions.Events.RedirectToIdentityProviderForSignOut(redirectContext).ConfigureAwait(false);

            // Assert event called
            await redirectFuncMock.ReceivedWithAnyArgs().Invoke(Arg.Any<RedirectContext>()).ConfigureAwait(false);
            await ((ITokenAcquisitionInternal)tokenAcquisitionMock).ReceivedWithAnyArgs().RemoveAccountAsync(Arg.Any<RedirectContext>()).ConfigureAwait(false);
        }
    }
}