using System.Security.Cryptography;
using CistaNAS.Web.Identity;
using CistaNAS.Web.Models;
using CistaNAS.Web.Volume;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace CistaNAS.Web.Services;

public sealed partial class VolumeService
{
    public Task<VolumeInfo> CreateAsync(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateName(name);
        // CreateInternalAsync 内部で _mountGate を取得するため、ここでは取得しない
        return CreateInternalAsync(name, username, password, encrypted);
    }

    /// <summary>
    /// サーバー側暗号化（AES-XTS で volume.dat を暗号化）の要否を決定する。
    /// "server" / "e2ee"（ボリューム暗号化 + クライアント側 E2EE を重ねる）→ true、"none" → false。
    /// ユーザー設定が未設定（null / 空）なら既定 "server" 扱いで requested を尊重する。
    /// 回帰 (Critical): 旧実装は `!= "server"` 比較のため、既定値 "server" のユーザーが
    /// encrypted=true で作成しても shouldEncrypt が false になり、「サーバー暗号化」ボリュームが
    /// 平文 volume.dat として作成されていた。
    /// </summary>
    internal static bool ResolveServerSideEncryption(bool requested, string? userEncryptionMode)
        => requested && userEncryptionMode != "none";

    /// <summary>ホームボリューム等、内部用途の作成（home__ プレフィックスを許可）。</summary>
    public Task<VolumeInfo> CreateInternalAsync(string name, string? username, string? password, bool encrypted = true)
    {
        ValidateStorageName(name);
        // 内部呼び出し（CreateUserAsync 等）では ValidateName をスキップ。
        // home__ / group__ プレフィックスや長さ制限を許可する。
        // CreateAsync 経由の場合は事前に ValidateName が呼ばれている。
        return UnderMountGateAsync(async () =>
        {
            // ユーザー設定を取得して暗号化モードとアルゴリズムを決定
            string cipherAlgorithm = "aes-256-xts";  // デフォルト
            bool shouldEncrypt = encrypted;
            string? userEncryptionMode = null;

            if (encrypted && !string.IsNullOrEmpty(username))
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = await userManager.FindByNameAsync(username);
                if (user is not null)
                {
                    userEncryptionMode = user.DefaultEncryptionMode;
                    if (!string.IsNullOrEmpty(user.DefaultCipherAlgorithm))
                    {
                        cipherAlgorithm = user.DefaultCipherAlgorithm;
                    }
                }
            }

            shouldEncrypt = ResolveServerSideEncryption(encrypted, userEncryptionMode);

            if (shouldEncrypt) { ArgumentException.ThrowIfNullOrEmpty(username); ArgumentException.ThrowIfNullOrEmpty(password); }

            if (await _metaStore.ExistsAsync(name))
                throw new VolumeException($"ボリューム '{name}' は既に存在します。");

            var (header, masterKey) = VolumeHeader.Create(name, username, password, VolOpts.SectorSize, VolOpts.ToKdfSpec(), shouldEncrypt, cipherAlgorithm);

            // チャンクモード判定: "auto" かつ S3 プロバイダ使用時
            bool chunkMode = ShouldUseChunkMode();
            if (chunkMode)
            {
                header.StorageMode = "chunk";
                header.ServerChunkSize = VolOpts.ServerChunkSize;
            }

            Directory.CreateDirectory(VolumeDir(name));
            await _metaStore.SaveAsync(name, header);

            if (chunkMode)
            {
                // チャンクモード: volume.dat は作成しない
                MountInternalChunked(name, header, masterKey);
            }
            else
            {
                File.Create(GetDataPath(name)).Dispose();
                MountInternal(name, header, masterKey);
            }

            return ToInfo(name, header, true);
        });
    }

    public Task<VolumeInfo> MountAsync(string name, string username, string? password)
    {
        ValidateStorageName(name);
        return UnderMountGateAsync(async () =>
        {
            if (_mounted.ContainsKey(name))
                throw new VolumeException($"ボリューム '{name}' は既にマウントされています。");

            var header = await LoadHeaderOrThrowAsync(name);
            byte[]? masterKey = null;
            if (header.Encrypted)
            {
                ArgumentException.ThrowIfNullOrEmpty(username);
                ArgumentException.ThrowIfNullOrEmpty(password);
                masterKey = header.UnwrapMasterKey(username, password)
                    ?? throw new VolumeException("認証情報が正しくありません。");

                // 二相コミット再ラップの第 2 相完了前にプロセスが死んだ場合、Previous* ラップ
                // （旧パスワード）がヘッダに永続化したまま残る。現行ラップでのアンラップに成功
                // した今、このユーザーの Previous* は確実に中断物なので撤去して保存する
                // （撤去しないと侵害後のパスワード変更でも旧資格情報がボリュームに対して有効なまま）。
                if (header.ClearStalePreviousWrap(username))
                {
                    await _metaStore.SaveAsync(name, header);
                    _logger.LogInformation(
                        "ボリューム '{Volume}' に残留した Previous ラップを検出・撤去しました（ユーザー: {Username}）。",
                        name, username);
                }
            }

            if (header.StorageMode == "chunk")
                MountInternalChunked(name, header, masterKey);
            else
                MountInternal(name, header, masterKey);

            // クラッシュ復旧: 未コミットジャーナルがあればカタログを修復してクリア
            await RecoverMountedVolumeAsync(name);

            return ToInfo(name, header, true);
        });
    }

    /// <summary>ボリュームをロック（アンマウント）する。オーナーのみ実行可能。</summary>
    public Task LockAsync(string name, string username)
    {
        ValidateStorageName(name);
        ArgumentException.ThrowIfNullOrEmpty(username);
        return UnderMountGateAsync(async () =>
        {
            if (!_mounted.TryGetValue(name, out var mv))
                throw new VolumeException($"ボリューム '{name}' はマウントされていません。");

            if (mv.Header.OwnerUser != username)
                throw new VolumeException("オーナーのみがボリュームをロックできます。");

            // 新規 I/O の受付を停止してから TryRemove する（レースによる use-after-dispose 防止）。
            // Close 後に TryGetValue が成功した I/O は EnterAsync で拒否される。
            mv.IoTracker.Close();
            _mounted.TryRemove(name, out _);
            // 既存のアクティブ I/O の完了を待機してからストリームを破棄
            await mv.IoTracker.WaitForZeroAsync();
            mv.Stream.Dispose();
            if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
        });
    }

    /// <summary>ボリューム情報を返す。存在しない場合は null。</summary>
    public async Task<VolumeInfo?> GetVolumeInfoAsync(string name)
    {
        var header = await LoadHeaderIfExistsAsync(name);
        if (header is null) return null;
        return ToInfo(name, header, _mounted.ContainsKey(name));
    }

    /// <summary>ボリュームヘッダを返す。存在しない場合は例外。</summary>
    public async Task<VolumeHeader> GetVolumeHeaderAsync(string name) => await LoadHeaderOrThrowAsync(name);

    /// <summary>指定ユーザーがアクセスできるボリューム一覧を返す。</summary>
    public async Task<IReadOnlyList<VolumeInfo>> ListForUserAsync(string username)
    {
        var result = new List<VolumeInfo>();
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        var userGroups = await GetGroupsForUserAsync(username);

        foreach (var name in volumeNames)
        {
            var header = await LoadHeaderIfExistsAsync(name);
            if (header is null) continue;

            if (!HasAccessInternal(header, username, userGroups)) continue;

            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    public async Task<IReadOnlyList<VolumeInfo>> ListAllAsync()
    {
        var result = new List<VolumeInfo>();
        var volumeNames = await _metaStore.ListVolumeNamesAsync();

        foreach (var name in volumeNames)
        {
            var header = await LoadHeaderIfExistsAsync(name);
            if (header is null) continue;
            result.Add(ToInfo(name, header, _mounted.ContainsKey(name)));
        }
        return result;
    }

    /// <summary>ボリュームを削除する。username が非 null の場合はオーナーまたは admin のみ実行可能。</summary>
    public Task DeleteVolumeAsync(string name, string? username = null, bool isAdmin = false)
    {
        ValidateStorageName(name);
        return UnderMountGateAsync(async () =>
        {
            VolumeHeader? existingHeader = null;
            // 認可: username が指定されている場合はオーナーまたは admin に限定
            if (username is not null && !isAdmin)
            {
                existingHeader = await LoadHeaderOrThrowAsync(name);
                if (existingHeader.OwnerUser != username)
                    throw new VolumeException("オーナーのみがボリュームを削除できます。");
            }
            else
            {
                // アンマウント済みボリュームでも StorageMode を確認し、
                // チャンクストアの残存データを取りこぼさない。
                existingHeader = await LoadHeaderIfExistsAsync(name);
            }
            // 新規 I/O の受付を停止してから TryRemove（レースによる use-after-dispose 防止）
            if (_mounted.TryGetValue(name, out var closing))
                closing.IoTracker.Close();

            if (_mounted.TryRemove(name, out var mv))
            {
                await mv.IoTracker.WaitForZeroAsync();
                mv.Stream.Dispose();
                if (mv.MasterKey is not null) CryptographicOperations.ZeroMemory(mv.MasterKey);
            }

            // メタデータと実データの削除をマウントゲート内で実行
            // （アンマウントと削除の間に別リクエストが介入するのを防止）。
            // 先に実データを削除し、最後に volume.json を削除する。
            // 途中で失敗した場合でもヘッダを残して再試行可能にし、
            // 「削除成功」を返したのにデータが残る状態を避ける。

            // ローカルの volume.dat を削除
            string dataPath = GetDataPath(name);
            if (File.Exists(dataPath))
                File.Delete(dataPath);

            // チャンクモード: S3 からボリューム配下の全チャンクを削除
            // ヘッダが既に欠損した孤児ボリュームでは、残存チャンクを
            // 回収できるよう削除を試みる（通常の local ボリュームでは
            // chunk プレフィックスは空なので副作用はない）。
            if (existingHeader is null || (closing?.Header ?? existingHeader)?.StorageMode == "chunk")
                await _chunkStore.DeleteVolumeChunksAsync(name);

            // メタデータを最後に削除。VolumeMetadataStore は volume.json を
            // 列挙結果の末尾で削除するため、障害時の再試行に必要なヘッダを保つ。
            await _metaStore.DeleteAllAsync(name);

            // ロックを解除（ボリューム削除後は不要）
            try { _metaStore.Storage.RemoveLock(name); }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のロック解除に失敗しました。", name); }

            // 空になったローカルディレクトリを掃除
            string dir = VolumeDir(name);
            if (Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                Directory.Delete(dir);

            // ストリームロック・カタログロック・E2EEファイルゲートを解放
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var fileService = scope.ServiceProvider.GetRequiredService<FileService>();
                FileService.RemoveStreamLock(name);
                FileService.RemoveCatalogLock(name);

                var e2eeFs = scope.ServiceProvider.GetRequiredService<E2eeFileService>();
                e2eeFs.CleanupVolumeGates(name);
            }
            catch (Exception ex) { _logger.LogWarning(ex, "ボリューム '{Volume}' のリソース解放に失敗しました。", name); }
        });
    }
}
