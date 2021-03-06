﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Microsoft.Identity.Web.TokenCacheProviders.Session
{
    /// <summary>
    /// An implementation of token cache for Confidential clients backed by an Http session.
    /// </summary>
    /// For this session cache to work effectively the aspnetcore session has to be configured properly.
    /// The latest guidance is provided at https://docs.microsoft.com/aspnet/core/fundamentals/app-state
    ///
    /// // In the method - public void ConfigureServices(IServiceCollection services) in startup.cs, add the following
    /// services.AddSession(option =>
    /// {
    ///	    option.Cookie.IsEssential = true;
    /// });
    ///
    /// In the method - public void Configure(IApplicationBuilder app, IHostingEnvironment env) in startup.cs, add the following
    ///
    /// app.UseSession(); // Before UseMvc()
    ///
    /// <seealso>https://aka.ms/msal-net-token-cache-serialization</seealso>
    public class MsalSessionTokenCacheProvider : MsalAbstractTokenCacheProvider, IMsalTokenCacheProvider
    {
        private HttpContext CurrentHttpContext => _httpContextAccessor.HttpContext;
        private ILogger _logger;

        /// <summary>
        /// Msal Token cache provider constructor
        /// </summary>
        /// <param name="microsoftIdentityOptions">Configuration options</param>
        /// <param name="httpContextAccessor">accessor for an HttpContext</param>
        /// <param name="logger">Logger</param>
        public MsalSessionTokenCacheProvider(
            IOptions<MicrosoftIdentityOptions> microsoftIdentityOptions,
            IHttpContextAccessor httpContextAccessor,
            ILogger<MsalSessionTokenCacheProvider> logger) : 
            base(microsoftIdentityOptions, httpContextAccessor)
        {
            _logger = logger;
        }

        /// <summary>
        /// Read a blob representing the token cache from its key
        /// </summary>
        /// <param name="cacheKey">Key representing the token cache
        /// (account or app)</param>
        /// <returns>Read blob</returns>
        protected override async Task<byte[]> ReadCacheBytesAsync(string cacheKey)
        {
            await CurrentHttpContext.Session.LoadAsync().ConfigureAwait(false);

            s_sessionLock.EnterReadLock();
            try
            {
                if (CurrentHttpContext.Session.TryGetValue(cacheKey, out byte[] blob))
                {
                    _logger.LogInformation($"Deserializing session {CurrentHttpContext.Session.Id}, cacheId {cacheKey}");
                }
                else
                {
                    _logger.LogInformation($"CacheId {cacheKey} not found in session {CurrentHttpContext.Session.Id}");
                }
                return blob;
            }
            finally
            {
                s_sessionLock.ExitReadLock();
            }
        }

        /// <summary>
        /// Writes the token cache identitied by its key to the serialization mechanism
        /// </summary>
        /// <param name="cacheKey">key for the cache (account ID or app ID)</param>
        /// <param name="bytes">blob to write to the cache</param>
        protected override async Task WriteCacheBytesAsync(string cacheKey, byte[] bytes)
        {
            s_sessionLock.EnterWriteLock();
            try
            {
                _logger.LogInformation($"Serializing session {CurrentHttpContext.Session.Id}, cacheId {cacheKey}");

                // Reflect changes in the persistent store
                CurrentHttpContext.Session.Set(cacheKey, bytes);
                await CurrentHttpContext.Session.CommitAsync().ConfigureAwait(false);
            }
            finally
            {
                s_sessionLock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Removes a cache described from its key
        /// </summary>
        /// <param name="cacheKey">key of the token cache (user account or app ID)</param>
        protected override async Task RemoveKeyAsync(string cacheKey)
        {
            s_sessionLock.EnterWriteLock();
            try
            {
                _logger.LogInformation($"Clearing session {CurrentHttpContext.Session.Id}, cacheId {cacheKey}");

                // Reflect changes in the persistent store
                CurrentHttpContext.Session.Remove(cacheKey);
                await CurrentHttpContext.Session.CommitAsync().ConfigureAwait(false);
            }
            finally
            {
                s_sessionLock.ExitWriteLock();
            }
        }

        private static readonly ReaderWriterLockSlim s_sessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
    }
}
