using Xunit;

namespace ArgonGuard.Passwords.Tests;

public class SkeletonTests
{
    [Fact]
    public void SpecVersion_IsDefined()
    {
        Assert.False(string.IsNullOrEmpty(SpecVersion.Value));
    }
}
