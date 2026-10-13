using System.Net.Http.Json;

namespace CistaNAS.Wasm.Services;

public sealed class ApplicationUpdateApiClient(HttpClient http)
{
    public async Task<ApplicationUpdateStatus?> GetStatusAsync(CancellationToken ct = default)
    {
        using var response = await http.GetAsync("/api/v1/admin/update", ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ApplicationUpdateStatus>(cancellationToken: ct);
    }

    public async Task<ApplicationUpdateStatus?> RequestUpdateAsync(string? version = null, CancellationToken ct = default)
    {
        using var response = await http.PostAsJsonAsync("/api/v1/admin/update", new UpdateRequest(version), ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ApplicationUpdateStatus>(cancellationToken: ct);
    }

    public async Task<ApplicationUpdateStatus?> CheckForUpdatesAsync(CancellationToken ct = default)
    {
        using var response = await http.PostAsync("/api/v1/admin/update/check", content: null, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ApplicationUpdateStatus>(cancellationToken: ct);
    }

    private sealed record UpdateRequest(string? Version);
}

public sealed record ApplicationUpdateStatus(
    string State,
    string? CurrentVersion,
    string? LatestVersion,
    bool UpdateAvailable,
    string? RequestedVersion,
    DateTimeOffset? CheckedAt,
    string? Message
);
