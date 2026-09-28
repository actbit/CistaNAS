using System.Security.Cryptography;
using CistaNAS.Shared.Crypto;
using CistaNAS.Web.Configuration;
using CistaNAS.Web.Models;
using CistaNAS.Web.Services;
using CistaNAS.Web.Storage;
using CistaNAS.Web.Volume;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace CistaNAS.Tests;

/// <summary>
/// E2EE ボリューム（クライアント保持 masterKey、サーバーは暗号文のみ）の
/// 「通常フローでデータが一切欠損しないこと」の検証。
/// サーバー側に平文が存在しないため、検証は「wrap から masterKey を復元 → fileKey 導出 →
/// チャンク復号 → 元データとバイト比較」というクライアントと同じ本物の復号経路で行う:
/// - マウントサイクル（Lock → MountE2ee）を跨いでも全チャンクが復号・バイト等価
/// - 削除・チャンク差し替え（replace）後も最新内容が正しく、他のデータが無傷
/// - パスワード KDF（PBKDF2 / Argon2id）や ECDH 共有のどの鍵経路でも masterKey が失われない
/// </summary>
public class E2eeDataNoLossTests : IAsyncDisposable
{
    private const string Owner = "alice";
    private const string OwnerPassword = "alice-pw";
    private const string Member = "bob";
    private const string MemberKeyPassword = "bob-key-pass";
    private const int ChunkSize = 4096;

    // Argon2id を含む KDF をテストで高速に回すための軽量 spec（本番値ではない）
    private static readonly KdfSpec FastSpec = new("pbkdf2-sha256", 10_000, 0, 0, 0);

    private readonly string _dataRoot;
    private readonly IServiceProvider _sp;
    private readonly VolumeService _vs;
    private readonly byte[] _masterKey;

    public E2eeDataNoLossTests()
    {
        (_sp, _dataRoot) = TestHelper.BuildTestServices();
        _vs = _sp.GetRequiredService<VolumeService>();
        _masterKey = RandomNumberGenerator.GetBytes(32);
    }

    private E2eeFileService GetE2eeFileService()
    {
        using var scope = _sp.CreateAsyncScope();
        var opt = _sp.GetRequiredService<IOptions<CistaNasOptions>>();
        var storage = _sp.GetRequiredService<IStorageProvider>();
        var chunkStore = _sp.GetRequiredService<IChunkStore>();
        return new E2eeFileService(_vs, storage, chunkStore, opt);
    }

    /// <summary>決定論的な疑似ランダムデータを生成する（テストの再実行性のため）。</summary>
    private static byte[] DeterministicBytes(int length, int seed)
    {
        var data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    /// <summary>Owner の password wrap 付き E2EE ボリュームを作成する。</summary>
    private async Task CreateOwnedVolumeAsync(string name, byte[]? masterKey = null, KdfSpec? spec = null)
    {
        KdfSpec kdf = spec ?? KdfSpec.LegacyPbkdf2(1000);
        byte[] mk = masterKey ?? _masterKey;
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] kek = E2eeCrypto.DeriveKek(Owner, OwnerPassword, salt, kdf);
        var (nonce, ct, tag) = E2eeCrypto.WrapMasterKey(mk, kek);
        CryptographicOperations.ZeroMemory(kek);

        await _vs.CreateE2eeAsync(name, Owner, new VolumeHeader.UserWrappedKey
        {
            WrapType = "password",
            Kdf = new()
            {
                Algorithm = kdf.Algorithm,
                Iterations = kdf.Iterations,
                MemoryKiB = kdf.MemoryKiB,
                TimeCost = kdf.TimeCost,
                Parallelism = kdf.Parallelism,
                Salt = salt,
            },
            WrappedMasterKey = new()
            {
                Algorithm = "aes-256-gcm",
                Nonce = nonce,
                Ciphertext = ct,
                Tag = tag,
            },
        }, chunkSize: ChunkSize);
    }

    /// <summary>平文を E2EE チャンク列に暗号化してアップロードし、確定（Finalize）まで行う。
    /// クライアント（WASM / Dokan / Mobile）が実施する通常アップロードフローと同じ手順。</summary>
    private static async Task<string> WritePlainFileAsync(E2eeFileService e2eeFs, string vol,
        byte[] masterKey, string plainName, byte[] plain)
    {
        byte[] fileSalt = E2eeCrypto.GenerateFileSalt();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);
        int chunkCount = E2eeCrypto.ComputeChunkCount(plain.Length, ChunkSize);
        int encLen = (int)E2eeCrypto.ComputeEncryptedLength(plain.Length, ChunkSize);

        var entry = await e2eeFs.CreateFileAsync(vol,
            new E2eeCreateFileRequest(E2eeCrypto.EncryptFilename(plainName, masterKey), encLen, chunkCount), Owner);

        int offset = 0;
        for (int i = 0; i < chunkCount; i++)
        {
            int len = Math.Min(ChunkSize, plain.Length - offset);
            byte[] plainChunk = new byte[len];
            Array.Copy(plain, offset, plainChunk, 0, len);
            byte[] enc = E2eeCrypto.EncryptChunk(plainChunk, fileKey, i, fileSalt, isFirstChunk: i == 0);
            using var ms = new MemoryStream(enc);
            await e2eeFs.UploadChunkAsync(vol, entry.FileId, i, ms, enc.Length);
            offset += len;
        }

        await e2eeFs.FinalizeFileAsync(vol, entry.FileId, new E2eeFinalizeFileRequest(encLen));
        return entry.FileId;
    }

    /// <summary>カタログから全チャンクをダウンロードして復号し、平文全体を組み立てる。
    /// fileSalt は先頭チャンクの先頭 16 バイト（平文で埋め込まれている）から取得する —
    /// これが実際のクライアントが任意のファイルを復号する経路と同じ。</summary>
    private static async Task<byte[]> ReadPlainFileAsync(E2eeFileService e2eeFs, string vol,
        byte[] masterKey, string fileId)
    {
        var entry = (await e2eeFs.ListFilesAsync(vol)).Files.Single(f => f.FileId == fileId);
        int chunkCount = entry.ChunkSizes.Count;

        // 先頭チャンクを取得して fileSalt（先頭 16 バイトの平文領域）を取り出す。
        // DownloadChunkAsync が返す Revision は replace で進むため、復号時に必ずそれを使う
        var (firstStream, firstLen, firstRev, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] firstEnc = new byte[firstLen];
        using (firstStream) await firstStream.ReadExactlyAsync(firstEnc);
        byte[] fileSalt = firstEnc.AsSpan(0, 16).ToArray();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(masterKey, fileSalt);

        // 復号結果: 暗号化長から salt(16) とチャンク毎のタグ(16) を除いた長さ
        byte[] plain = new byte[entry.EncryptedLength - 16 - chunkCount * 16];
        int offset = 0;
        for (int i = 0; i < chunkCount; i++)
        {
            byte[] enc;
            int revision;
            if (i == 0)
            {
                enc = firstEnc;
                revision = firstRev;
            }
            else
            {
                var (stream, len, rev, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, i);
                enc = new byte[len];
                using (stream) await stream.ReadExactlyAsync(enc);
                revision = rev;
            }
            byte[] dec = E2eeCrypto.DecryptChunk(enc, fileKey, i, fileSalt, revision: revision);
            Array.Copy(dec, 0, plain, offset, dec.Length);
            offset += dec.Length;
        }
        CryptographicOperations.ZeroMemory(fileKey);
        return plain;
    }

    /// <summary>保存済み password wrap から、指定パスワードで masterKey を復元する
    /// （WrappedKeyResponse DTO 経由 — クライアント API と同じ形）。</summary>
    private static async Task<byte[]> UnwrapOwnerMasterKeyAsync(VolumeService vs, string vol, string password)
    {
        var entry = await vs.GetWrappedKeyAsync(vol, Owner);
        Assert.NotNull(entry);
        Assert.Equal("password", entry!.WrapType);
        byte[] salt = Convert.FromBase64String(entry.Kdf.Salt);
        byte[] kek = E2eeCrypto.DeriveKek(Owner, password, salt,
            new KdfSpec(entry.Kdf.Algorithm, entry.Kdf.Iterations, entry.Kdf.MemoryKiB,
                entry.Kdf.Parallelism, entry.Kdf.TimeCost));
        try
        {
            return E2eeCrypto.UnwrapMasterKey(
                Convert.FromBase64String(entry.WrappedMasterKey.Nonce),
                Convert.FromBase64String(entry.WrappedMasterKey.Ciphertext),
                Convert.FromBase64String(entry.WrappedMasterKey.Tag),
                kek, entry.WrappedMasterKey.Algorithm);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>bob の identity 鍵を導出・登録し、秘密鍵を返す（呼び出し側で ZeroMemory すること）。</summary>
    private async Task<byte[]> RegisterMemberIdentityAsync(string username = Member)
    {
        await using var scope = _sp.CreateAsyncScope();
        var account = scope.ServiceProvider.GetRequiredService<AccountService>();
        await account.CreateUserAsync(username, $"{username}-login-pw", "user");
        var identity = await account.GetOrCreateEcdhIdentityAsync(username);
        var (pub, priv) = EcdhIdentityKey.DeriveKeyPair(username, MemberKeyPassword, identity.IdentitySalt, FastSpec);
        await account.UpdatePublicKeyAsync(username, Convert.ToBase64String(pub));
        return priv;
    }

    /// <summary>owner が member 宛てに ECDH wrap を作成・登録する。</summary>
    private async Task<VolumeHeader.UserWrappedKey> GrantEcdhAsync(string vol, byte[] masterKey, byte[] memberPublicKey, string member = Member)
    {
        var (eph, nonce, ct, tag) = E2eeCrypto.EcdhWrap(masterKey, memberPublicKey);
        var wrap = new VolumeHeader.UserWrappedKey
        {
            WrapType = "ecdh",
            Kdf = new() { Algorithm = "none" },
            WrappedMasterKey = new() { Algorithm = "aes-256-gcm", Nonce = nonce, Ciphertext = ct, Tag = tag },
            EphemeralPublicKey = eph,
        };
        await _vs.AddE2eeWrappedKeyAsync(vol, Owner, member, wrap);
        return wrap;
    }

    /// <summary>member 側で保存済み ECDH wrap を秘密鍵で解いて masterKey を復元する。</summary>
    private static async Task<byte[]> UnwrapMemberMasterKeyAsync(VolumeService vs, string vol,
        byte[] memberPrivateKey, string member = Member)
    {
        var entry = await vs.GetWrappedKeyAsync(vol, member);
        Assert.NotNull(entry);
        Assert.Equal("ecdh", entry!.WrapType);
        return E2eeCrypto.EcdhUnwrap(
            Convert.FromBase64String(entry.WrappedMasterKey.Nonce),
            Convert.FromBase64String(entry.WrappedMasterKey.Ciphertext),
            Convert.FromBase64String(entry.WrappedMasterKey.Tag),
            Convert.FromBase64String(entry.EphemeralPublicKey!), memberPrivateKey);
    }

    // ---- 通常フロー: マウントサイクルでのデータ保持 ----

    /// <summary>マルチチャンクファイル（4096B × 3 チャンク）が、Lock → MountE2ee の再マウントを
    /// 跨いでも復号結果が元の平文とバイト等価であること。サーバー側は暗号文しか持たないため、
    /// これは「鍵経路（wrap → unwrap → fileKey 導出）とチャンク保存の両方が無傷」の完全検証になる。</summary>
    [Fact]
    public async Task MultiChunkFile_LockRemount_DecryptByteIdentical()
    {
        string vol = "e2ee-persist-multi";
        await CreateOwnedVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] plain = DeterministicBytes(10_000, seed: 101);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "report.dat", plain);

        // アンマウント → 再マウント（E2EE は unwrap を伴わない再マウント）
        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);

        Assert.Equal(_masterKey, await UnwrapOwnerMasterKeyAsync(_vs, vol, OwnerPassword));
        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, fileId);
        Assert.Equal(plain, actual);
    }

    /// <summary>2 ファイル中 1 つを削除した後、残りのファイルが再マウントを跨いでも
    /// 復号結果がバイト等価で残ること。</summary>
    [Fact]
    public async Task TwoFiles_DeleteOne_Remount_OtherDecryptsIdentically()
    {
        string vol = "e2ee-persist-delete";
        await CreateOwnedVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] keep = DeterministicBytes(8_192, seed: 111);
        byte[] doomed = DeterministicBytes(5_000, seed: 112);
        string keepId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "keep.bin", keep);
        string doomedId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "doomed.bin", doomed);

        await e2eeFs.DeleteFileAsync(vol, doomedId);

        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);

        var files = (await e2eeFs.ListFilesAsync(vol)).Files;
        Assert.Single(files);
        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, keepId);
        Assert.Equal(keep, actual);
    }

    /// <summary>チャンク差し替え（replace=true、revision 進行）の後、再マウントしても
    /// 常に「最新の内容」が復号されること（旧 revision が読まれる退行の防止）。</summary>
    [Fact]
    public async Task ReplaceChunk_Remount_LatestContentDecrypts()
    {
        string vol = "e2ee-persist-replace";
        await CreateOwnedVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] v1 = DeterministicBytes(ChunkSize, seed: 121);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "single.bin", v1);

        // 保存済み先頭チャンクから fileSalt を取得し、同サイズの内容 v2 に差し替え（revision=1）
        var (firstStream, firstLen, _, _) = await e2eeFs.DownloadChunkAsync(vol, fileId, 0);
        byte[] firstEnc = new byte[firstLen];
        using (firstStream)
            await firstStream.ReadExactlyAsync(firstEnc);
        byte[] fileSalt = firstEnc.AsSpan(0, 16).ToArray();
        byte[] fileKey = E2eeCrypto.DeriveFileKey(_masterKey, fileSalt);

        byte[] v2 = DeterministicBytes(ChunkSize, seed: 122);
        byte[] encV2 = E2eeCrypto.EncryptChunk(v2, fileKey, 0, fileSalt, isFirstChunk: true, revision: 1);
        using (var ms = new MemoryStream(encV2))
            await e2eeFs.UploadChunkAsync(vol, fileId, 0, ms, encV2.Length, replace: true);
        var (_, rev) = await e2eeFs.GetChunkHashAsync(vol, fileId, 0);
        Assert.Equal(1, rev);

        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);

        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, fileId);
        Assert.Equal(v2, actual);
    }

    // ---- ファイル名（カタログ）の欠損防止 ----

    /// <summary>実運用を想定した実名（日本語・絵文字・空白・先頭ドット・長名）が、
    /// 暗号化カタログ経由の再マウント後も 1 つも欠けずに内容ごと復元できること。</summary>
    [Fact]
    public async Task RealisticFilenames_CatalogRoundtripThroughRemount()
    {
        string vol = "e2ee-persist-names";
        await CreateOwnedVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        string[] names =
        [
            "レポート 2026年度.docx",
            "写真 🎉🏔️.jpg",
            "空白 入り ファイル.txt",
            ".隠し設定ファイル",
            new string('長', 120) + ".bin",
        ];
        var contents = new Dictionary<string, byte[]>();
        int seed = 500;
        foreach (string name in names)
        {
            byte[] data = DeterministicBytes(100 + name.Length * 3, seed++);
            contents[name] = data;
            await WritePlainFileAsync(e2eeFs, vol, _masterKey, name, data);
        }

        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);

        var files = (await e2eeFs.ListFilesAsync(vol)).Files;
        Assert.Equal(names.Length, files.Count);
        foreach (var f in files)
        {
            string plainName = E2eeCrypto.DecryptFilename(f.EncryptedName, _masterKey);
            Assert.True(contents.TryGetValue(plainName, out var expected),
                $"復号されたファイル名「{plainName}」は元のカタログに存在しない");
            byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, f.FileId);
            Assert.Equal(expected, actual);
        }
    }

    // ---- 鍵経路（KDF / 共有）での masterKey 保持 ----

    /// <summary>誤パスワード由来の KEK では wrap を解けず、正しい KEK では解ける —
    /// すなわちデータの生死が「パスワードの正しさ」に正確に紐づくこと。</summary>
    [Fact]
    public async Task WrongPasswordUnwrapFails_CorrectPasswordRestoresData()
    {
        string vol = "e2ee-persist-wrongpw";
        await CreateOwnedVolumeAsync(vol);
        var e2eeFs = GetE2eeFileService();

        byte[] plain = DeterministicBytes(6_000, seed: 131);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "secret.dat", plain);

        var entry = await _vs.GetWrappedKeyAsync(vol, Owner);
        Assert.NotNull(entry);
        byte[] salt = Convert.FromBase64String(entry!.Kdf.Salt);

        // 誤パスワード → AEAD タグ検証失敗で復号不能。重要なのは「誤鍵で解けてしまわない」こと。
        byte[] wrongKek = E2eeCrypto.DeriveKek(Owner, "totally-wrong", salt,
            new KdfSpec(entry.Kdf.Algorithm, entry.Kdf.Iterations, entry.Kdf.MemoryKiB,
                entry.Kdf.Parallelism, entry.Kdf.TimeCost));
        try
        {
            Assert.ThrowsAny<CryptographicException>(() => E2eeCrypto.UnwrapMasterKey(
                Convert.FromBase64String(entry.WrappedMasterKey.Nonce),
                Convert.FromBase64String(entry.WrappedMasterKey.Ciphertext),
                Convert.FromBase64String(entry.WrappedMasterKey.Tag),
                wrongKek, entry.WrappedMasterKey.Algorithm));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrongKek);
        }

        // 正しいパスワードで復元し、データ読取まで完全に成功する
        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);
        byte[] restored = await UnwrapOwnerMasterKeyAsync(_vs, vol, OwnerPassword);
        Assert.Equal(_masterKey, restored);
        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, restored, fileId);
        Assert.Equal(plain, actual);
    }

    /// <summary>Argon2id（合成）wrap のボリュームでも、再マウント後の unwrap → 復号が
    /// バイト等価で成功すること（新 KDF 経路での通常フロー保証）。</summary>
    [Fact]
    public async Task Argon2idWrapVolume_Remount_UnwrapAndDecryptWorks()
    {
        string vol = "e2ee-persist-argon2id";
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        // 引数順: (Algorithm, Iterations, MemoryKiB, Parallelism, TimeCost)
        var spec = new KdfSpec(KdfSpec.Argon2id, 10, 1024, 1, 1);
        await CreateOwnedVolumeAsync(vol, masterKey: masterKey, spec: spec);
        var e2eeFs = GetE2eeFileService();

        byte[] plain = DeterministicBytes(9_000, seed: 141);
        string fileId = await WritePlainFileAsync(e2eeFs, vol, masterKey, "argon.dat", plain);

        // ヘッダに Argon2id 種別が永続化されていること
        var header = await _vs.GetVolumeHeaderAsync(vol);
        Assert.Equal(KdfSpec.Argon2id, header.UserKeys[Owner].Kdf.Algorithm);

        await _vs.LockAsync(vol, Owner);
        await _vs.MountE2eeAsync(vol, Owner);

        Assert.Equal(masterKey, await UnwrapOwnerMasterKeyAsync(_vs, vol, OwnerPassword));
        byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, masterKey, fileId);
        Assert.Equal(plain, actual);
    }

    /// <summary>ECDH 共有を受けたメンバー（bob）が、identity 秘密鍵による unwrap →
    /// ファイル復号までを実データで完結できること（owner のデータとバイト等価）。</summary>
    [Fact]
    public async Task EcdhSharedVolume_MemberDecryptsFileByteIdentical()
    {
        string vol = "e2ee-persist-share";
        await CreateOwnedVolumeAsync(vol);
        byte[] priv = await RegisterMemberIdentityAsync();
        try
        {
            // owner がファイルを書き、bob 宛て ECDH wrap を追加（通常の共有フロー）
            var e2eeFs = GetE2eeFileService();
            byte[] plain = DeterministicBytes(12_345, seed: 151);
            string fileId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "shared-report.dat", plain);

            var identity = await _sp.GetRequiredService<AccountService>()
                .GetOrCreateEcdhIdentityAsync(Member);
            var (pub, _) = EcdhIdentityKey.DeriveKeyPair(Member, MemberKeyPassword, identity.IdentitySalt, FastSpec);
            await GrantEcdhAsync(vol, _masterKey, pub);

            // 再マウントサイクルを挟む（サーバー再起動相当の状態でメンバーが取りに来る）
            await _vs.LockAsync(vol, Owner);
            await _vs.MountE2eeAsync(vol, Owner);

            // bob 側: wrap 取得 → 秘密鍵で unwrap → 復号
            byte[] bobMasterKey = await UnwrapMemberMasterKeyAsync(_vs, vol, priv);
            Assert.Equal(_masterKey, bobMasterKey);
            byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, bobMasterKey, fileId);
            Assert.Equal(plain, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    /// <summary>ECDH 共有の revoke → 再付与サイクルでも、owner のデータが 1 バイトも欠損しないこと
    /// （revoke は owner の wrap もファイルも触らない・再付与でメンバーが再度読める）。</summary>
    [Fact]
    public async Task EcdhSharedVolume_RevokeReGrant_OwnerDataIntact()
    {
        string vol = "e2ee-persist-revoke";
        await CreateOwnedVolumeAsync(vol);
        byte[] priv = await RegisterMemberIdentityAsync();
        try
        {
            var e2eeFs = GetE2eeFileService();
            byte[] plain = DeterministicBytes(7_000, seed: 161);
            string fileId = await WritePlainFileAsync(e2eeFs, vol, _masterKey, "cycle.dat", plain);

            var identity = await _sp.GetRequiredService<AccountService>()
                .GetOrCreateEcdhIdentityAsync(Member);
            var (pub, _) = EcdhIdentityKey.DeriveKeyPair(Member, MemberKeyPassword, identity.IdentitySalt, FastSpec);
            var bobWrap = await GrantEcdhAsync(vol, _masterKey, pub);

            // revoke: bob から wrap が消える（ファイルカタログは無傷）
            await _vs.RevokeAccessAsync(vol, Owner, Member);
            Assert.Null(await _vs.GetWrappedKeyAsync(vol, Member));
            Assert.Single((await e2eeFs.ListFilesAsync(vol)).Files);

            // 再付与（同一 ECDH wrap — 秘密鍵側の再導出は不要）
            await _vs.AddE2eeWrappedKeyAsync(vol, Owner, Member, bobWrap);
            byte[] bobMasterKey = await UnwrapMemberMasterKeyAsync(_vs, vol, priv);
            Assert.Equal(_masterKey, bobMasterKey);

            // サイクル全体を通じて owner のデータは無傷
            byte[] actual = await ReadPlainFileAsync(e2eeFs, vol, _masterKey, fileId);
            Assert.Equal(plain, actual);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(priv);
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var v in await _vs.ListAllAsync())
        {
            try
            {
                var header = await _vs.GetVolumeHeaderAsync(v.Name);
                await _vs.LockAsync(v.Name, header.OwnerUser);
            }
            catch (Exception) { }
        }
        try { if (Directory.Exists(_dataRoot)) Directory.Delete(_dataRoot, recursive: true); } catch (Exception) { }
    }
}
