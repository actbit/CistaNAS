using CistaNAS.Web.Configuration;
using CistaNAS.Web.Services;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

public sealed class TemporaryAccessLifecycleTests
{
    [Fact]
    public async Task Host_StartsCleanupOnTheSameServicesUsedByRequests()
    {
        string root = Path.Combine(Path.GetTempPath(), "cista-temporary-access-" + Guid.NewGuid().ToString("N"));
        try
        {
            var options = new CistaNasOptions { DataRoot = root };
            using var host = new HostBuilder().ConfigureServices(services =>
            {
                services.AddSingleton(Options.Create(options));
                services.AddCistaNasServices(options);
            }).Build();
            await host.StartAsync();
            try
            {
                var invitations = host.Services.GetRequiredService<InvitationService>();
                var tokens = host.Services.GetRequiredService<StreamingTokenService>();
                var hosted = host.Services.GetServices<IHostedService>().ToList();
                Assert.Contains(hosted, service => ReferenceEquals(service, invitations));
                Assert.Contains(hosted, service => ReferenceEquals(service, tokens));
                Assert.NotNull(invitations.ExecuteTask);
                Assert.NotNull(tokens.ExecuteTask);
                Assert.False(invitations.ExecuteTask.IsCompleted);
                Assert.False(tokens.ExecuteTask.IsCompleted);
            }
            finally { await host.StopAsync(); }
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExpiredInvitation_CannotBeRetrievedBeforeBackgroundCleanup(bool accepted)
    {
        using var service = new InvitationService();
        var invitation = service.Create("owner", "recipient");
        if (accepted) service.SetAcceptedData(invitation.InvitationId, "key", "nonce");
        invitation.CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromHours(25);
        Assert.Null(service.Find(invitation.InvitationId));
    }

    [Fact]
    public void ExpiredInvitation_CannotBeAcceptedWithoutCallingFind()
    {
        using var service = new InvitationService();
        var invitation = service.Create("owner", "recipient");
        invitation.CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromHours(25);
        Assert.Throws<InvalidOperationException>(() => service.SetAcceptedData(invitation.InvitationId, "key", "nonce"));
        Assert.Null(invitation.AcceptedAt);
        Assert.Null(invitation.EncryptedPublicKey);
    }

    [Fact]
    public void InvitationNearExpiry_CanStillBeAcceptedExactlyOnce()
    {
        using var service = new InvitationService();
        var invitation = service.Create("owner", "recipient");
        invitation.CreatedAt = DateTimeOffset.UtcNow - TimeSpan.FromHours(23);
        service.SetAcceptedData(invitation.InvitationId.ToUpperInvariant(), "key", "nonce");
        Assert.Equal("key", service.Find(invitation.InvitationId)!.EncryptedPublicKey);
        Assert.Throws<InvalidOperationException>(() => service.SetAcceptedData(invitation.InvitationId, "new-key", "new-nonce"));
    }
}
