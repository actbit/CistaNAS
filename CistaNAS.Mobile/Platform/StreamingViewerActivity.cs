using Android.App;
using Android.Content.PM;
using Android.Graphics;
using Android.Graphics.Pdf;
using Android.Media;
using Android.OS;
using Android.Views;
using Android.Widget;
using CistaNAS.Mobile.Core.Services;
using Orientation = Android.Widget.Orientation;

namespace CistaNAS.Mobile.Platform;

[Activity(Name = "com.cistanas.mobile.StreamingViewerActivity", Exported = false,
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize)]
public sealed class StreamingViewerActivity : Activity
{
    private string? _id;
    private ReadOnlyFileContent? _content;
    private CancellationTokenRegistration _closedRegistration;
    private MediaPlayer? _player;
    private StreamingMediaDataSource? _media;
    private bool _prepared;
    private bool _resumed;
    private SurfaceCallbacks? _surfaceCallbacks;
    private PdfRenderer? _pdf;
    private StreamingPdfDescriptor? _pdfDescriptor;
    private readonly SemaphoreSlim _pdfGate = new(1, 1);
    private Bitmap? _pageBitmap;
    private ImageView? _pageImage;
    private int _page;
    private bool _destroyed;
    private TextView _status = null!;
    private Button _play = null!;
    private SeekBar _seek = null!;
    private bool _seeking;
    private Handler? _positionHandler;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        Window?.SetFlags(WindowManagerFlags.Secure, WindowManagerFlags.Secure);
        var layout = new LinearLayout(this) { Orientation = Orientation.Vertical };
        layout.SetPadding(20, 20, 20, 20);
        var back = new Button(this) { Text = "閉じる" };
        back.Click += (_, _) => Finish();
        layout.AddView(back);
        _status = new TextView(this) { Text = "準備中...", TextSize = 16 };
        layout.AddView(_status);
        SetContentView(layout);
        try
        {
            _id = Intent?.GetStringExtra("content-id") ?? throw new InvalidDataException("ファイル情報がありません。");
            _content = AndroidFileViewerLauncher.Files.Get(_id);
            Title = _content.Name;
            _closedRegistration = _content.Cancellation.Register(() => RunOnUiThread(Finish));
            if (_content.MimeType == "application/pdf") OpenPdf(layout);
            else OpenMedia(layout);
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void OpenMedia(LinearLayout layout)
    {
        _player = new MediaPlayer();
        _media = new StreamingMediaDataSource(_content!);
        _player.SetDataSource(_media);
        _play = new Button(this) { Text = "再生", Enabled = false };
        _play.Click += (_, _) =>
        {
            if (!_prepared || _player is null) return;
            if (_player.IsPlaying) _player.Pause(); else _player.Start();
            _play.Text = _player.IsPlaying ? "一時停止" : "再生";
        };
        _seek = new SeekBar(this) { Max = 1000, Enabled = false };
        _seek.StartTrackingTouch += (_, _) => _seeking = true;
        _seek.StopTrackingTouch += (_, _) =>
        {
            _seeking = false;
            if (_prepared && _player is not null) _player.SeekTo((int)((long)_player.Duration * _seek.Progress / 1000));
        };
        _player.Prepared += (_, _) =>
        {
            if (_destroyed) return;
            _prepared = true;
            _play.Enabled = _seek.Enabled = true;
            _status.Text = _content!.Name;
            if (_resumed) { _player.Start(); _play.Text = "一時停止"; }
            _positionHandler = new Handler(Looper.MainLooper!);
            UpdatePosition();
        };
        _player.Completion += (_, _) => { if (!_destroyed) _play.Text = "再生"; };
        _player.Error += (_, e) =>
        {
            e.Handled = true;
            ShowError(new IOException("この動画・音声を再生できませんでした。形式と接続を確認してください。"));
        };
        if (_content!.MimeType.StartsWith("video/", StringComparison.Ordinal))
        {
            var surface = new SurfaceView(this);
            _surfaceCallbacks = new SurfaceCallbacks(this);
            surface.Holder!.AddCallback(_surfaceCallbacks);
            layout.AddView(surface, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1));
        }
        else _player.PrepareAsync();
        layout.AddView(_seek);
        layout.AddView(_play);
    }

    private void UpdatePosition()
    {
        if (_destroyed || !_prepared || _player is null) return;
        if (!_seeking && _player.Duration > 0) _seek.Progress = (int)((long)_player.CurrentPosition * 1000 / _player.Duration);
        _positionHandler?.PostDelayed(UpdatePosition, 500);
    }

    private void OpenPdf(LinearLayout layout)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26))
            throw new NotSupportedException("PDFの表示にはAndroid 8以降が必要です。");
        _pageImage = new ImageView(this);
        _pageImage.SetScaleType(ImageView.ScaleType.FitCenter);
        layout.AddView(_pageImage, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1));
        var controls = new LinearLayout(this) { Orientation = Orientation.Horizontal };
        var previous = new Button(this) { Text = "前のページ" };
        var next = new Button(this) { Text = "次のページ" };
        previous.Click += async (_, _) => await RenderPdfAsync(-1);
        next.Click += async (_, _) => await RenderPdfAsync(1);
        controls.AddView(previous);
        controls.AddView(next);
        layout.AddView(controls);
        _ = RenderPdfAsync(0);
    }

    private async Task RenderPdfAsync(int direction)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26)) return;
        try
        {
            var bitmap = await Task.Run(async () =>
            {
                if (!OperatingSystem.IsAndroidVersionAtLeast(26)) throw new PlatformNotSupportedException();
                await _pdfGate.WaitAsync(_content!.Cancellation).ConfigureAwait(false);
                try
                {
                    if (_pdf is null)
                    {
                        _pdfDescriptor = new StreamingPdfDescriptor(_content);
                        _pdf = new PdfRenderer(_pdfDescriptor.Descriptor);
                    }
                    _page = Math.Clamp(_page + direction, 0, _pdf.PageCount - 1);
                    using var page = _pdf.OpenPage(_page);
                    float scale = Math.Min(2f, 1600f / Math.Max(page.Width, page.Height));
                    var image = Bitmap.CreateBitmap(Math.Max(1, (int)(page.Width * scale)),
                        Math.Max(1, (int)(page.Height * scale)), Bitmap.Config.Argb8888!)!;
                    try
                    {
                        image.EraseColor(Color.White);
                        page.Render(image, null, null, PdfRenderMode.ForDisplay);
                        return image;
                    }
                    catch { image.Recycle(); image.Dispose(); throw; }
                }
                finally { _pdfGate.Release(); }
            });
            if (_destroyed) { bitmap.Recycle(); bitmap.Dispose(); return; }
            _pageImage!.SetImageBitmap(bitmap);
            _pageBitmap?.Recycle();
            _pageBitmap?.Dispose();
            _pageBitmap = bitmap;
            _status.Text = $"{_content!.Name} — {_page + 1} / {_pdf!.PageCount}";
        }
        catch (Exception ex) { ShowError(ex); }
    }

    private void ShowError(Exception ex)
    {
        if (!_destroyed) RunOnUiThread(() => { if (!_destroyed) _status.Text = ex.Message; });
    }

    protected override void OnPause()
    {
        _resumed = false;
        if (_prepared && _player?.IsPlaying == true) { _player.Pause(); _play.Text = "再生"; }
        base.OnPause();
    }

    protected override void OnResume()
    {
        base.OnResume();
        _resumed = true;
    }

    protected override void OnDestroy()
    {
        _destroyed = true;
        _positionHandler?.RemoveCallbacksAndMessages(null);
        _closedRegistration.Dispose();
        if (_id is not null) AndroidFileViewerLauncher.Files.Remove(_id);
        _player?.Release();
        _player?.Dispose();
        _media?.Dispose();
        _pdfGate.Wait();
        try
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(26))
            {
                _pdf?.Close();
                _pdf?.Dispose();
                _pdfDescriptor?.Dispose();
            }
            _pageBitmap?.Recycle();
            _pageBitmap?.Dispose();
        }
        finally { _pdfGate.Release(); }
        _surfaceCallbacks?.Dispose();
        _positionHandler?.Dispose();
        base.OnDestroy();
    }

    private sealed class SurfaceCallbacks(StreamingViewerActivity activity) : Java.Lang.Object, ISurfaceHolderCallback
    {
        private bool _preparing;
        public void SurfaceCreated(ISurfaceHolder holder)
        {
            activity._player?.SetDisplay(holder);
            if (!_preparing) { _preparing = true; activity._player?.PrepareAsync(); }
        }
        public void SurfaceChanged(ISurfaceHolder holder, Android.Graphics.Format format, int width, int height) { }
        public void SurfaceDestroyed(ISurfaceHolder holder)
        {
            if (activity._prepared && activity._player?.IsPlaying == true) activity._player.Pause();
            activity._player?.SetDisplay(null);
        }
    }
}
