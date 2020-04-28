// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web.Test.Common;
using Microsoft.Identity.Web.TokenCacheProviders;
using NSubstitute;
using Xunit;

namespace Microsoft.Identity.Web.Test
{
    public class TokenAcquisitionTests
    {
        private TokenAcquisition _tokenAcq;

        public TokenAcquisitionTests()
        {
            _tokenAcq = new TokenAcquisition(
                Substitute.For<IMsalTokenCacheProvider>(),
                Substitute.For<IHttpContextAccessor>(),
                Substitute.For<IOptions<MicrosoftIdentityOptions>>(),
                Substitute.For<IOptions<ConfidentialClientApplicationOptions>>(),
                Substitute.For<IHttpClientFactory>(),
                Substitute.For<ILogger<TokenAcquisition>>()
                );
            //var builder = Substitute.For<AbstractAcquireTokenParameterBuilder<AcquireTokenForClientParameterBuilder>>();
            //_tokenAcq._application = Substitute.For<IConfidentialClientApplication>();
            //_tokenAcq._application.AcquireTokenForClient(Arg.Any<IEnumerable<string>>()).Returns(builder);
            //builder.ExecuteAsync(Arg.Any<CancellationToken>()).Returns(Task.CompletedTask);
        }

        [Fact]
        public void BuildConfidentialClientApplicationAsync()
        {
            // CCABuild with redirect uri
            //      with B2C authority
            //      With AAD authority
            // caches initialized
        }

        [Fact]
        public async void GetAccessTokenForAppAsync_Throws()
        {
            await Assert.ThrowsAsync<ArgumentNullException>("scopes", () => _tokenAcq.GetAccessTokenForAppAsync(null));
        }

        [Fact]
        public async void MockConfidentialClientApplication_Exception()
        {
            // Setup up a confidential client application that returns throws
            var mockApp = Substitute.For<IConfidentialClientApplication>();
            mockApp
                .WhenForAnyArgs(x => x.AcquireTokenByAuthorizationCode(Arg.Any<string[]>(), Arg.Any<string>())?.ExecuteAsync(CancellationToken.None))
                .Do(x => throw new Exception("my message"));

            // Now call the substitute and check the exception is thrown
            var ex = await Assert.ThrowsAsync<Exception>(
                () => mockApp
                    .AcquireTokenForClient(new string[] { "scope1" })
                    .WithAuthority("")
                    .ExecuteAsync(CancellationToken.None));
            Assert.Equal("my message", ex.Message);
        }

        [Fact]
        public async void GetAccessTokenForAppAsync_DoesntThrow()
        {


            //var token = await _tokenAcq.GetAccessTokenForAppAsync(TestConstants.s_scopesForApp);
            //Assert.NotNull(token);
        }


        [Fact]
        public void AddAccountToCacheFromAuthorizationCodeAsync()
        {
            throw new NotImplementedException();

            // Null context, scopes > throws
            // Handlecoderedemption is called twice
            // Add scopes to user
            //? Call CCA.AcquireTokenByAuthorizationCode - No, impl detail
        }

        [Fact]
        public void GetAccessTokenForUserAsync()
        {
            throw new NotImplementedException();

            // Null scopes > throws
            // GetAccessTokenOnBehalfOfUserFromCacheAsync throws MsalUiRequiredError
            //      Token in context is null
            //          rethrow
            //      token in context is not null
            //          Inner token is null
            //          Inner token is not null
            //      ? call AcquireTokenOnBehalfOf > returns token
            // GetAccessTokenOnBehalfOfUserFromCacheAsync succeeds
            //      claimsPrincipal.GetMsalAccountId != null
            //          finds account
            //          !_microsoftIdentityOptions.IsB2C and didn't find account
            //              loginhint == null > throws
            //              get accounts based on loginhint
            //      claimsPrincipal.GetMsalAccountId == null, _microsoftIdentityOptions.IsB2C
            //          Getaccount by useflow
            //      
            //      null scopes > throws
            //      IsB2C
            //          build authority, AcquireTokenSilent, return token
            //      !IsB2C, tenant is not null
            //          build aad authority, AcquireTokenSilent, return token
            //       !IsB2C, tenant is null
            //          AcquireTokenSilent, return token
        }

        [Fact]
        public void RemoveAccountAsync()
        {
            throw new NotImplementedException();

            // B2C acc is not in cache
            // Non-B2C acc is not in cache, null account and non-nullaccount
        }

        [Fact]
        public void ReplyForbiddenWithWwwAuthenticateHeader()
        {
            throw new NotImplementedException();

            //msalServiceException.ErrorCode == MsalError.InvalidGrantError and AcceptedTokenVersionMismatch > throws
            // CurrentHttpContext.Response has correct header WWWAuthenticate
        }
    }
}
