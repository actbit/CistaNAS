using System.Collections.Concurrent;
using System.Security.Cryptography;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Crypto;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.Options;

namespace CistaNAS.Web.Services;

/// <summary>
/// ボリュームの作成・マウント・ロックを管理する Singleton Service。
/// マウント状態（Stream）をプロセス内に保持し、Blazor と /api/v1 で共有する。
/// 暗号化ボリュームの KEK は「ユーザー名＋パスワード」のハッシュから導出。
/// </summary>
public sealed class VolumeService
{
    private readonly string _dataRoot;
    private readonly VolumeOptions _volOpts;

    private readonly ConcurrentDictionary<string, MountedVolume> _mounted = new();

    public VolumeService(IOptions<CistaNasOptions> options)
    {
        _dataRoot = options.Value.DataRoot;
        _volOpts = options.Value.Volume;
        Directory.CreateDirectory(_dataRoot);
    }

    public VolumeInfo Create(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateName(name);
        if (encrypted)
        {
            ArgumentException.ThrowIfNullOrEmpty(username);
            ArgumentException.ThrowIfNullOrEmpty(password);
        }

        string dir = VolumeDir(name);
        if (Directory.Exists(dir))
            throw new VolumeException($"ボリューム '{name}' は既に存在します。");

        var (header, masterKey) = VolumeHeader.Create(name, username, password, _volOpts.SectorSize, _volOpts.KdfIterations, encrypted);

        Directory.CreateDirectory(dir);
        header.Save(Path.Combine(dir, VolumeHeader.FileName));

        File.Create(GetDataPath(name)).Dispose();

        MountInternal(name, header, masterKey);

        return new VolumeInfo(name, true, encrypted, header.OwnerUser, header.CreatedAt);
    }

    public VolumeInfo Mount(string name, string username, string? password)
    {
        if (_mounted.ContainsKey(name))
            throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

        string headerPath = Path.Combine(VolumeDir(name), VolumeHeader.FileName);
        if (!File.Exists(headerPath))
            throw new VolumeException($"ボリューム '{name}' が見つかりません。");

        var header = VolumeHeader.Load(headerPath);

        byte[]? masterKey = null;
        if (header.Encrypted)
        {
            ArgumentException.ThrowIfNullOrEmpty(username);
            ArgumentException.ThrowIfNullOrEmpty(password);
            masterKey = header.UnwrapMasterKey(username, password)
                ?? throw new VolumeException("認証情報が正しくありません。");
        }

        MountInternal(name, header, masterKey);
        return new VolumeInfo(name, true, header.Encrypted, header.OwnerUser, header.CreatedAt);
    }

    public void Lock(string name)
    {
        if (!_mounted.TryRemove(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");

        mv.Stream.Dispose();
        if (mv.MasterKey is not null)
            CryptographicOperations.ZeroMemory(mv.MasterKey);
    }

    public IReadOnlyList<VolumeInfo> ListMounted()
    {
        var result = new List<VolumeInfo>(_mounted.Count);
        foreach ((string name, var mv) in _mounted)
            result.Add(new VolumeInfo(name, true, mv.Encrypted, mv.OwnerUser, mv.CreatedAt));
        return result;
    }

    public IReadOnlyList<VolumeInfo> ListAll()
    {
        var result = new List<VolumeInfo>();
        if (!Directory.Exists(_dataRoot)) return result;

        foreach (var dir in Directory.EnumerateDirectories(_dataRoot))
        {
            string name = Path.GetFileName(dir);
            string headerPath = Path.Combine(dir, VolumeHeader.FileName);
            if (!File.Exists(headerPath)) continue;

            var header = VolumeHeader.Load(headerPath);
            result.Add(new VolumeInfo(name, _mounted.ContainsKey(name), header.Encrypted, header.OwnerUser, header.CreatedAt));
        }
        return result;
    }

    public (Stream Stream, VolumeHeader Header) GetMounted(string name)
    {
        if (!_mounted.TryGetValue(name, out var mv))
            throw new VolumeException($"ボリューム '{name}' はマウントされていません。");
        return (mv.Stream, mv.Header);
    }

    public bool IsMounted(string name) => _mounted.ContainsKey(name);

    private void MountInternal(string name, VolumeHeader header, byte[]? masterKey)
    {
        string dataPath = GetDataPath(name);
        var fs = new FileStream(dataPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        Stream stream;
        if (header.Encrypted && masterKey is not null)
        {
            stream = new AesXtsStream(fs, masterKey, header.SectorSize, fs.Length, writable: true);
        }
        else
        {
            stream = fs;
        }

        _mounted[name] = new MountedVolume(header, masterKey, stream);
    }

    private string VolumeDir(string name) => Path.Combine(_dataRoot, name);
    private string GetDataPath(string name) => Path.Combine(VolumeDir(name), "volume.dat");

    private static void ValidateName(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        if (name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
            throw new VolumeException("ボリューム名に使用できない文字が含まれています。");
        if (name.Length > 64)
            throw new VolumeException("ボリューム名は 64 文字以内にしてください。");
    }

    private sealed class MountedVolume(VolumeHeader header, byte[]? masterKey, Stream stream)
    {
        public VolumeHeader Header { get; } = header;
        public byte[]? MasterKey { get; } = masterKey;
        public Stream Stream { get; } = stream;
        public bool Encrypted { get; } = header.Encrypted;
        public string OwnerUser { get; } = header.OwnerUser;
        public DateTimeOffset CreatedAt { get; } = header.CreatedAt;
    }
}
