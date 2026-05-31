namespace CistaNAS.Web.Storage;

/// <summary>
/// チャンク単位のオブジェクトストレージ抽象。
/// ボリュームのファイルデータを S3/R2 等にチャンク分割して保存する。
/// IStorageProvider を内部で使用し、キーパターン {volumeName}/chunks/{objectId}/{chunkIndex} で管理。
/// </summary>
public interface IChunkStore
{
    /// <summary>チャンクを書き込む。</summary>
    Task WriteChunkAsync(string volumeName, string objectId, int chunkIndex, Stream data, CancellationToken ct = default);

    /// <summary>チャンクを読み込む。存在しない場合は null。</summary>
    Task<byte[]?> ReadChunkAsync(string volumeName, string objectId, int chunkIndex, CancellationToken ct = default);

    /// <summary>チャンクを同期的に読み込む。存在しない場合は null。Stream.Read の同期パスで使用。</summary>
    byte[]? ReadChunk(string volumeName, string objectId, int chunkIndex);

    /// <summary>指定オブジェクトの全チャンクインデックスを列挙する（昇順）。</summary>
    Task<IReadOnlyList<int>> ListChunksAsync(string volumeName, string objectId, CancellationToken ct = default);

    /// <summary>指定オブジェクトの全チャンクを削除する。</summary>
    Task DeleteChunksAsync(string volumeName, string objectId, CancellationToken ct = default);

    /// <summary>ボリューム配下の全チャンクを一括削除する（ボリューム削除時）。</summary>
    Task DeleteVolumeChunksAsync(string volumeName, CancellationToken ct = default);
}
