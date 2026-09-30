namespace CistaNAS.Mobile.Core.Services;

/// <summary>同一プロセスの表示画面にだけ、RAM内の読み取りソースを渡す。</summary>
public sealed class StreamingFileRegistry
{
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _files = [];

    public string Add(ReadOnlyFileContent content)
    {
        string id = Guid.NewGuid().ToString("N");
        var entry = new Entry(content);
        lock (_gate)
        {
            content.Cancellation.ThrowIfCancellationRequested();
            _files.Add(id, entry);
        }
        // Navigation can cancel before Android creates the Activity, or Android can
        // refuse a background launch. The Activity must not be required for cleanup.
        var registration = content.Cancellation.Register(() => Remove(id));
        bool retained;
        lock (_gate)
        {
            retained = _files.TryGetValue(id, out var current) && ReferenceEquals(current, entry);
            if (retained) entry.Registration = registration;
        }
        if (!retained) registration.Dispose();
        content.Cancellation.ThrowIfCancellationRequested();
        return id;
    }

    public ReadOnlyFileContent Get(string id)
    {
        lock (_gate)
        {
            if (!_files.TryGetValue(id, out var entry)) throw new FileNotFoundException("表示が終了しました。");
            entry.Content.Cancellation.ThrowIfCancellationRequested();
            return entry.Content;
        }
    }

    public void Remove(string id)
    {
        Entry? entry;
        lock (_gate) _files.Remove(id, out entry);
        entry?.Dispose();
    }

    public void Clear()
    {
        Entry[] contents;
        lock (_gate)
        {
            contents = [.. _files.Values];
            _files.Clear();
        }
        foreach (var content in contents) content.Dispose();
    }

    private sealed class Entry(ReadOnlyFileContent content) : IDisposable
    {
        public ReadOnlyFileContent Content { get; } = content;
        public CancellationTokenRegistration Registration { get; set; }
        public void Dispose() { Registration.Dispose(); Content.Dispose(); }
    }
}
