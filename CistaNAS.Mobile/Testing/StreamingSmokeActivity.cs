using System.Net;
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Graphics;
using Android.Graphics.Pdf;
using Android.Media;
using Android.OS;
using Android.Util;
using Android.Widget;
using CistaNAS.Client.Api;
using CistaNAS.Mobile.Core.Services;
using CistaNAS.Mobile.Platform;
using CistaNAS.Shared.Crypto;
using Encoding = System.Text.Encoding;

namespace CistaNAS.Mobile.Testing;

// Opt-in Debug test APK only; excluded from normal builds.
[Activity(Name = "com.cistanas.mobile.StreamingSmokeActivity", Exported = true)]
public sealed class StreamingSmokeActivity : Activity
{
    private LinearLayout _layout = null!;
    private Fixture? _viewerFixture;
    protected override async void OnCreate(Bundle? state)
    {
        base.OnCreate(state);
        var status = new TextView(this) { Text = "Native streaming tests running" };
        _layout = new LinearLayout(this) { Orientation = Android.Widget.Orientation.Vertical };
        _layout.AddView(status);
        SetContentView(_layout);
        try
        {
            if (Intent?.GetStringExtra("viewer") is string mode)
            {
                byte[] fixture = mode == "pdf" ? MakePdf() : mode == "audio" ? MakeWave() : await LoadVideoAsync();
                string name = mode == "pdf" ? "test.pdf" : mode == "audio" ? "tone.wav" : "clip.mp4";
                _viewerFixture = await Fixture.CreateAsync(name, fixture);
                await new AndroidFileViewerLauncher().LaunchAsync(_viewerFixture.Content);
                return;
            }
            string cache = Application.Context.CacheDir!.AbsolutePath;
            var before = Directory.GetFiles(cache, "*", SearchOption.AllDirectories).ToHashSet();
            await TestMediaAsync("tone.wav", MakeWave());
            await TestMediaAsync("clip.mp4", await LoadVideoAsync());
            await TestPdfAsync();
            var added = Directory.GetFiles(cache, "*", SearchOption.AllDirectories).Where(path => !before.Contains(path)).ToArray();
            if (added.Length != 0) throw new InvalidOperationException("Viewer created cache files: " + string.Join(",", added));
            Log.Info("CistaNASSmoke", "PASS audio, video, seek, PDF, cancellation, no cache files");
            status.Text = "PASS native streaming";
        }
        catch (Exception ex) { Log.Error("CistaNASSmoke", "FAIL " + ex); status.Text = "FAIL " + ex.Message; }
    }

    private async Task<byte[]> LoadVideoAsync()
    {
        using var asset = Assets!.Open("viewer-video.enc");
        using var encrypted = new MemoryStream();
        await asset.CopyToAsync(encrypted);
        byte[] packed = encrypted.ToArray();
        byte[] video = new byte[packed.Length - 28];
        using var aes = new AesGcm(new byte[32], 16);
        aes.Decrypt(packed.AsSpan(0, 12), packed.AsSpan(28), packed.AsSpan(12, 16), video);
        return video;
    }

    protected override void OnDestroy()
    {
        _viewerFixture?.Dispose();
        base.OnDestroy();
    }

    private async Task TestMediaAsync(string name, byte[] bytes)
    {
        using var fixture = await Fixture.CreateAsync(name, bytes);
        using var source = new StreamingMediaDataSource(fixture.Content);
        byte[] probe = new byte[64];
        if (source.ReadAt(fixture.Content.Length, probe, 0, probe.Length) != -1) throw new IOException("Media EOF");
        using var player = new MediaPlayer();
        Android.Views.SurfaceView? surface = null;
        SurfaceReady? surfaceCallback = null;
        if (name.EndsWith(".mp4", StringComparison.Ordinal))
        {
            surface = new Android.Views.SurfaceView(this);
            surfaceCallback = new SurfaceReady();
            surface.Holder!.AddCallback(surfaceCallback);
            _layout.AddView(surface, new LinearLayout.LayoutParams(200, 200));
            await surfaceCallback.Ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            player.SetDisplay(surface.Holder);
        }
        var prepared = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var seeked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        player.Prepared += (_, _) => prepared.TrySetResult();
        player.Completion += (_, _) => completed.TrySetResult();
        player.SeekComplete += (_, _) => seeked.TrySetResult();
        player.Error += (_, e) =>
        {
            e.Handled = true;
            var error = new IOException($"Native media error {e.What}/{e.Extra}");
            prepared.TrySetException(error); completed.TrySetException(error); seeked.TrySetException(error);
        };
        player.SetDataSource(source);
        player.PrepareAsync();
        await prepared.Task.WaitAsync(TimeSpan.FromSeconds(30));
        if (player.Duration < 500) throw new IOException("Missing media duration");
        player.SeekTo(player.Duration / 2);
        await seeked.Task.WaitAsync(TimeSpan.FromSeconds(10));
        player.Start();
        await completed.Task.WaitAsync(TimeSpan.FromSeconds(15));
        player.Release();
        if (surface is not null) { _layout.RemoveView(surface); surfaceCallback!.Dispose(); surface.Dispose(); }
        if (fixture.Requests < 2) throw new IOException("Streaming did not request later chunks");
        fixture.Content.Dispose();
        try { source.ReadAt(0, probe, 0, probe.Length); throw new IOException("Closed media was readable"); }
        catch (Java.IO.IOException) { }
        Log.Info("CistaNASSmoke", $"PASS {name} seek/play, encrypted chunk requests={fixture.Requests}");
    }

    private sealed class SurfaceReady : Java.Lang.Object, Android.Views.ISurfaceHolderCallback
    {
        public TaskCompletionSource Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void SurfaceCreated(Android.Views.ISurfaceHolder holder) => Ready.TrySetResult();
        public void SurfaceChanged(Android.Views.ISurfaceHolder holder, Android.Graphics.Format format, int width, int height) { }
        public void SurfaceDestroyed(Android.Views.ISurfaceHolder holder) { }
    }

    private static async Task TestPdfAsync()
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26)) throw new PlatformNotSupportedException();
        using var fixture = await Fixture.CreateAsync("test.pdf", MakePdf());
        await Task.Run(() =>
        {
            if (!OperatingSystem.IsAndroidVersionAtLeast(26)) throw new PlatformNotSupportedException();
            using var descriptor = new StreamingPdfDescriptor(fixture.Content);
            using var renderer = new PdfRenderer(descriptor.Descriptor);
            if (renderer.PageCount != 2) throw new IOException("PDF page count");
            for (int index = 1; index >= 0; index--)
            {
                using var page = renderer.OpenPage(index);
                using var bitmap = Bitmap.CreateBitmap(200, 200, Bitmap.Config.Argb8888!)!;
                bitmap.EraseColor(Color.White);
                page.Render(bitmap, null, null, PdfRenderMode.ForDisplay);
                if (bitmap.GetPixel(100, 100) == Color.White.ToArgb()) throw new IOException("PDF page not rendered");
                bitmap.Recycle();
            }
            renderer.Close();
        });
        Log.Info("CistaNASSmoke", $"PASS PDF reverse page render, encrypted chunk requests={fixture.Requests}");
    }

    private static byte[] MakeWave()
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        int samples = 16000 * 2;
        writer.Write(Encoding.ASCII.GetBytes("RIFF")); writer.Write(36 + samples * 2);
        writer.Write(Encoding.ASCII.GetBytes("WAVEfmt ")); writer.Write(16);
        writer.Write((short)1); writer.Write((short)1); writer.Write(16000); writer.Write(32000);
        writer.Write((short)2); writer.Write((short)16); writer.Write(Encoding.ASCII.GetBytes("data")); writer.Write(samples * 2);
        for (int i = 0; i < samples; i++) writer.Write((short)(Math.Sin(i * Math.PI * 2 * 440 / 16000) * 4000));
        return stream.ToArray();
    }

    private static byte[] MakePdf()
    {
        const string drawing = "0 0 0 rg 0 0 200 200 re f\n";
        string[] objects = [
            "<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 5 0 R >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents 5 0 R >>",
            $"<< /Length {drawing.Length} >>\nstream\n{drawing}endstream"
        ];
        var pdf = new StringBuilder("%PDF-1.4\n");
        var offsets = new List<int>();
        for (int i = 0; i < objects.Length; i++) { offsets.Add(pdf.Length); pdf.Append($"{i + 1} 0 obj\n{objects[i]}\nendobj\n"); }
        pdf.Append("%" + new string(' ', 4096) + "\n");
        int xref = pdf.Length;
        pdf.Append($"xref\n0 {objects.Length + 1}\n0000000000 65535 f \n");
        foreach (int offset in offsets) pdf.Append($"{offset:D10} 00000 n \n");
        pdf.Append($"trailer\n<< /Size {objects.Length + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        return Encoding.ASCII.GetBytes(pdf.ToString());
    }

    private sealed class Fixture : HttpMessageHandler
    {
        private readonly Dictionary<int, byte[]> _chunks = [];
        private HttpClient _http = null!;
        private E2eeSession _session = null!;
        public ReadOnlyFileContent Content { get; private set; } = null!;
        public int Requests { get; private set; }
        public static async Task<Fixture> CreateAsync(string name, byte[] plain)
        {
            var fixture = new Fixture();
            fixture._http = new HttpClient(fixture) { BaseAddress = new Uri("http://test/") };
            fixture._session = new E2eeSession();
            byte[] master = E2eeCrypto.GenerateMasterKey();
            byte[] salt = E2eeCrypto.GenerateFileSalt();
            byte[] key = E2eeCrypto.DeriveFileKey(master, salt);
            const int chunkSize = 1024;
            fixture._session.StoreKey("vol", master, chunkSize);
            for (int i = 0; i < E2eeCrypto.ComputeChunkCount(plain.Length, chunkSize); i++)
                fixture._chunks[i] = E2eeCrypto.EncryptChunk(plain.AsSpan(i * chunkSize,
                    Math.Min(chunkSize, plain.Length - i * chunkSize)).ToArray(), key, i, salt, isFirstChunk: i == 0);
            var entry = new E2eeFileEntry { FileId = "file", EncryptedName = "", ChunkCount = fixture._chunks.Count,
                EncryptedLength = E2eeCrypto.ComputeEncryptedLength(plain.Length, chunkSize) };
            fixture.Content = await new StreamingFileService(new CistaNasApiClient(fixture._http), fixture._session)
                .OpenE2eeFileAsync("vol", name, entry);
            CryptographicOperations.ZeroMemory(plain); CryptographicOperations.ZeroMemory(master); CryptographicOperations.ZeroMemory(key);
            return fixture;
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            Requests++;
            int index = int.Parse(request.RequestUri!.Segments[^1]);
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(_chunks[index]) };
            response.Headers.Add("X-Chunk-Revision", "0");
            return Task.FromResult(response);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) { Content?.Dispose(); _session?.Dispose(); }
            base.Dispose(disposing);
        }
    }
}
