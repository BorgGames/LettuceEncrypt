// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Internal.Dns;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class DnsTxtRetrieverTests
{
    private const string Sample =
        "nQiBgwABAAAAAQAAD19hY21lLWNoYWxsZW5nZQ5sZXR0dWNlZW5jcnlwdAd0ZXN0aW5nBW5vdmFzBGxpZmUAABAAAcAzAAYAAQAABLYAMgRiZWF1Am5zCmNsb3VkZmxhcmUDY29tAANkbnPAV4yNCZ0AACcQAAAJYAAJOoAAAAcI";

    [Fact]
    public void CanParseSample()
    {
        DnsTxtRecordRetriever.ParseDnsResponse(Convert.FromBase64String(Sample));
    }
}
