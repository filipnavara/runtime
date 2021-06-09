// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO;
using System.Reflection;
using Internal.Cryptography;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Algorithms.Tests
{
    [SkipOnPlatform(TestPlatforms.Browser, "Not supported on Browser")]
    public class RC4Tests
    {
        [Fact]
        public void TestVector()
        {
            byte[] key = "0102030405".HexToByteArray();
            byte[] expectedOutput = "b2396305f03dc027ccc3524a0a1118a8".HexToByteArray();

            byte[] input = new byte[expectedOutput.Length];

            using (var encryptor = RC4.CreateEncryptor(key))
            {
                var output = encryptor.TransformFinalBlock(input, 0, input.Length);
                Assert.Equal(expectedOutput, output);
            }
        }
    }
}
