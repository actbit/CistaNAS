namespace CistaNAS.Web.Storage;

/// <summary>チャンク削除のリトライヘルパー。FileService / E2eeFileService 共通。</summary>
internal static class ChunkStoreRetryExtensions
{
    /// <summary>
    /// チャンク削除を最大3回リトライ（指数バックオフ）。全失敗時は孤児チャンクを許容
    /// （カタログ削除は完了しているため、データ不整合にはならない）。
    /// </summary>
    public static async Task DeleteChunksWithRetryAsync(
        this IChunkStore store, string volumeName, string objectId, CancellationToken ct)
    {
        const int maxRetries = 3;
        for (int i = 0; i < maxRetries; i++)
        {
            try
            {
                await store.DeleteChunksAsync(volumeName, objectId, ct);
                return; // 成功時は即時リターン
            }
            catch (Exception)
            {
                if (i < maxRetries - 1)
                {
                    // 指数バックオフで待機
                    await Task.Delay(100 * (i + 1), ct);
                }
            }
        }
    }
}
