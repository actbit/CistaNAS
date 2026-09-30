using Android.OS;
using Android.OS.Storage;
using Android.Systems;
using CistaNAS.Mobile.Core.Services;
using System.Runtime.Versioning;

namespace CistaNAS.Mobile.Platform;

/// <summary>PdfRendererにシーク可能な仮想FDを渡す。実ファイルを作らず、必要な範囲だけ復号する。</summary>
[SupportedOSPlatform("android26.0")]
internal sealed class StreamingPdfDescriptor : IDisposable
{
    private readonly HandlerThread _thread = new("CistaNAS PDF reads");
    private readonly Handler _handler;
    private readonly Callback _callback;

    public StreamingPdfDescriptor(ReadOnlyFileContent content)
    {
        _thread.Start();
        _handler = new Handler(_thread.Looper!);
        _callback = new Callback(content);
        try
        {
            var manager = (StorageManager)Android.App.Application.Context.GetSystemService(Android.Content.Context.StorageService)!;
            Descriptor = manager.OpenProxyFileDescriptor(ParcelFileMode.ReadOnly, _callback, _handler);
        }
        catch { Dispose(); throw; }
    }

    public ParcelFileDescriptor Descriptor { get; } = null!;
    public void Dispose()
    {
        Descriptor?.Close();
        _thread.QuitSafely();
        _thread.Join();
        _handler.Dispose();
        _thread.Dispose();
        _callback.Dispose();
    }

    private sealed class Callback(ReadOnlyFileContent content) : ProxyFileDescriptorCallback
    {
        public override long OnGetSize() => content.Length;
        public override int OnRead(long offset, int size, byte[]? data)
        {
            try
            {
                if (data is null) throw new IOException();
                return content.ReadAsync(offset, data.AsMemory(0, size)).AsTask().GetAwaiter().GetResult();
            }
            catch (Exception) { throw new ErrnoException("read", OsConstants.Eio); }
        }
        public override void OnRelease() { }
    }
}
