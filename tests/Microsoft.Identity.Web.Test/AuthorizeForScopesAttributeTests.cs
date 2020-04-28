// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Microsoft.Identity.Web.Test
{
    public class AuthorizeForScopesAttributeTests
    {
        [Fact]
        public void OnException()
        {
            throw new NotImplementedException();

            // no MsalEx > unchanged context.Result
            // innerEx = MsalEx
            //      CanBeSolvedByReSignInOfUser
            //          no scopes > throws
            //          Scopes section != null
            //              config service == null > throws
            //              scopes != null > throws, bug? unneeded?
            //          Scopes not null > set
            //      build properties: add loginhint, claims
        }
    }
}
