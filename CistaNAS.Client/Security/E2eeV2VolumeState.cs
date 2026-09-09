using CistaNAS.Shared.Crypto;

namespace CistaNAS.Client.Security;

/// <summary>
/// 共有 E2EE crypto format v2 のボリューム鍵状態（VolumeId + epoch ごとの GroupKey）。
/// 全て SecureBuffer で保持し、Dispose 時にゼロクリアする（アンマウント時に破棄）。
/// </summary>
public sealed class E2eeV2VolumeState : IDisposable
{
    private readonly Dictionary<int, SecureBuffer> _groupKeys = new();

    public E2eeV2VolumeState(string volumeId, IReadOnlyDictionary<int, byte[]> groupKeys)
    {
        VolumeId = new SecureBuffer(System.Text.Encoding.UTF8.GetBytes(volumeId));
        foreach (var (epoch, key) in groupKeys)
        {
            if (key.Length != E2eeV2.GroupKeySize)
                throw new ArgumentException($"GroupKey epoch {epoch} のサイズが不正です ({key.Length}B)。");
            _groupKeys[epoch] = new SecureBuffer(key);
        }
    }

    public SecureBuffer VolumeId { get; }

    public string VolumeIdString => System.Text.Encoding.UTF8.GetString(VolumeId.Buffer);

    /// <summary>自分が保持する最新の epoch（新規書き込みに使う）。鍵が無ければ 0。</summary>
    public int CurrentEpoch => _groupKeys.Count == 0 ? 0 : _groupKeys.Keys.Max();

    public bool HasEpoch(int epoch) => _groupKeys.ContainsKey(epoch);

    /// <summary>指定 epoch の GroupKey を取得する (返り値の配列は変更しないこと。状態が所有する)。</summary>
    public byte[] GetGroupKey(int epoch) =>
        _groupKeys.TryGetValue(epoch, out var buf) ? buf.Buffer
            : throw new InvalidOperationException($"GroupKey epoch {epoch} がありません（このデータを読む権限がない可能性があります）。");

    public void Dispose()
    {
        VolumeId.Dispose();
        foreach (var buf in _groupKeys.Values)
            buf.Dispose();
        _groupKeys.Clear();
    }
}
