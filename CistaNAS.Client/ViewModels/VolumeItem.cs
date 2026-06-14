namespace CistaNAS.Client.ViewModels;

public class VolumeItem
{
    public required string Name { get; init; }
    public required string EncryptionMode { get; init; }
    public required bool IsMounted { get; init; }
    public bool Encrypted { get; init; }
    public string MountPoint { get; init; } = "";
    public string OwnerUser { get; init; } = "";
    public bool IsHome { get; init; }
    public List<string> AuthorizedUsers { get; init; } = [];
    public List<string> AuthorizedGroups { get; init; } = [];

    public string StatusText => IsMounted ? $"マウント済み ({MountPoint})" : "未マウント";
    public string EncryptionText => EncryptionMode is "e2ee" or "group-e2ee" ? "E2EE" : EncryptionMode == "server" ? "サーバー" : "なし";
    public bool IsE2ee => EncryptionMode is "e2ee" or "group-e2ee";
}
