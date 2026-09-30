using Android.Media;
using CistaNAS.Mobile.Core.Services;

namespace CistaNAS.Mobile.Platform;

/// <summary>MediaPlayerへ必要な範囲だけを供給する。Seekにも同じRAM／ネットワーク経路を使う。</summary>
internal sealed class StreamingMediaDataSource(ReadOnlyFileContent content) : MediaDataSource
{
    public override long Size => content.Length;
    public override int ReadAt(long position, byte[]? buffer, int offset, int size)
    {
        if (buffer is null) throw new Java.IO.IOException("読み取りバッファがありません。");
        try
        {
            int read = content.ReadAsync(position, buffer.AsMemory(offset, size)).AsTask().GetAwaiter().GetResult();
            return read == 0 && size > 0 ? -1 : read;
        }
        catch (Exception) { throw new Java.IO.IOException("ファイルを読み取れませんでした。"); }
    }
    public override void Close() => content.Dispose();
}
