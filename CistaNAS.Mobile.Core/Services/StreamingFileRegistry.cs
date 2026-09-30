namespace CistaNAS.Mobile.Core.Services;

/// <summary>同一プロセスの表示画面にだけ、RAM内の読み取りソースを渡す。</summary>
public sealed class StreamingFileRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, ReadOnlyFileContent> _files = [];

    public string Add(ReadOnlyFileContent content)
    {
        content.Cancellation.ThrowIfCancellationRequested();
        string id = Guid.NewGuid().ToString("N");
        lock (_gate) _files.Add(id, content);
        return id;
    }

    public ReadOnlyFileContent Get(string id)
    {
        lock (_gate)
        {
            if (!_files.TryGetValue(id, out var content)) throw new FileNotFoundException("表示が終了しました。");
            content.Cancellation.ThrowIfCancellationRequested();
            return content;
        }
    }

    public void Remove(string id)
    {
        ReadOnlyFileContent? content;
        lock (_gate) _files.Remove(id, out content);
        content?.Dispose();
    }

    public void Clear()
    {
        ReadOnlyFileContent[] contents;
        lock (_gate)
        {
            contents = [.. _files.Values];
            _files.Clear();
        }
        foreach (var content in contents) content.Dispose();
    }
}
