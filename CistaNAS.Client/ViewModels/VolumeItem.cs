namespace CistaNAS.Client.ViewModels;

public class VolumeItem
{
    public required string Name { get; init; }
    public required string EncryptionMode { get; init; }
    public required bool IsMounted { get; init; }
    public required string MountPoint { get; init; } = "";

    public string StatusText => IsMounted ? $"マウント済み ({MountPoint})" : "未マウント";
    public string EncryptionText => EncryptionMode == "e2ee" ? "E2EE" : EncryptionMode == "server" ? "サーバー" : "なし";
}
