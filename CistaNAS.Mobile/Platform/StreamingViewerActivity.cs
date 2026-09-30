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
    private bool _mediaFailed;
    private SurfaceView? _videoSurface;
    private SurfaceCallbacks? _surfaceCallbacks;
    private PdfRenderer? _pdf;
    private StreamingPdfDescriptor? _pdfDescriptor;
    private readonly SemaphoreSlim _pdfGate = new(1, 1);
    private Bitmap? _pageBitmap;
    private ImageView? _pageImage;
    private int _page;
    private int _pageCount;
    private bool _pdfRendering;
    private Button? _previousPage;
    private Button? _nextPage;
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
        _media = new StreamingMediaDataSource(_content!, () => RunOnUiThread(() =>
            MediaFailed(new IOException("ファイルを読み取れませんでした。接続を確認してください。"))));
        _player.SetDataSource(_media);
        _play = new Button(this) { Text = "再生", Enabled = false };
        _play.Click += (_, _) =>
        {
            if (!_prepared || _player is null) return;
            RunMediaAction(() =>
            {
                if (_player.IsPlaying) _player.Pause(); else _player.Start();
                _play.Text = _player.IsPlaying ? "一時停止" : "再生";
            });
        };
        _seek = new SeekBar(this) { Max = 1000, Enabled = false };
        _seek.StartTrackingTouch += (_, _) => _seeking = true;
        _seek.StopTrackingTouch += (_, _) =>
        {
            _seeking = false;
            if (_prepared && _player is not null) RunMediaAction(() =>
            {
                int duration = _player.Duration;
                if (duration > 0) _player.SeekTo((int)((long)duration * _seek.Progress / 1000));
            });
        };
        _player.Prepared += (_, _) =>
        {
            if (_destroyed || _mediaFailed) return;
            _prepared = true;
            _play.Enabled = true;
            _status.Text = _content!.Name;
            RunMediaAction(() =>
            {
                _seek.Enabled = _player.Duration > 0;
                if (_resumed) { _player.Start(); _play.Text = "一時停止"; }
                _positionHandler = new Handler(Looper.MainLooper!);
                UpdatePosition();
            });
        };
        _player.Completion += (_, _) => { if (!_destroyed) _play.Text = "再生"; };
        _player.Error += (_, e) =>
        {
            e.Handled = true;
            MediaFailed(new IOException("この動画・音声を再生できませんでした。形式と接続を確認してください。"));
        };
        if (_content!.MimeType.StartsWith("video/", StringComparison.Ordinal))
        {
            _videoSurface = new SurfaceView(this);
            _surfaceCallbacks = new SurfaceCallbacks(this);
            _videoSurface.Holder!.AddCallback(_surfaceCallbacks);
            layout.AddView(_videoSurface, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1));
        }
        else _player.PrepareAsync();
        layout.AddView(_seek);
        layout.AddView(_play);
    }

    private void UpdatePosition()
    {
        if (_destroyed || !_prepared || _mediaFailed || _player is null) return;
        RunMediaAction(() =>
        {
            int duration = _player.Duration;
            if (!_seeking && duration > 0) _seek.Progress = (int)((long)_player.CurrentPosition * 1000 / duration);
        });
        if (_prepared && !_mediaFailed) _positionHandler?.PostDelayed(UpdatePosition, 500);
    }

    private void RunMediaAction(Action action)
    {
        if (_destroyed || _mediaFailed) return;
        try { action(); }
        catch (Exception ex) { MediaFailed(ex); }
    }

    private void MediaFailed(Exception error)
    {
        if (_destroyed || _mediaFailed) return;
        _mediaFailed = true;
        _prepared = false;
        _positionHandler?.RemoveCallbacksAndMessages(null);
        if (_play is not null) _play.Enabled = false;
        if (_seek is not null) _seek.Enabled = false;
        // Reset is valid even in MediaPlayer's Error state and stops buffered
        // playback after a read failure that the decoder reported only as EOF.
        try { _player?.Reset(); }
        catch (Exception) { }
        ShowError(error);
    }

    private void OpenPdf(LinearLayout layout)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26))
            throw new NotSupportedException("PDFの表示にはAndroid 8以降が必要です。");
        _pageImage = new ImageView(this);
        _pageImage.SetScaleType(ImageView.ScaleType.FitCenter);
        layout.AddView(_pageImage, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, 0, 1));
        var controls = new LinearLayout(this) { Orientation = Orientation.Horizontal };
        _previousPage = new Button(this) { Text = "前のページ", Enabled = false };
        _nextPage = new Button(this) { Text = "次のページ", Enabled = false };
        _previousPage.Click += async (_, _) => await RenderPdfAsync(-1);
        _nextPage.Click += async (_, _) => await RenderPdfAsync(1);
        controls.AddView(_previousPage);
        controls.AddView(_nextPage);
        layout.AddView(controls);
        _ = RenderPdfAsync(0);
    }

    private async Task RenderPdfAsync(int direction)
    {
        if (!OperatingSystem.IsAndroidVersionAtLeast(26) || _destroyed || _pdfRendering) return;
        _pdfRendering = true;
        _previousPage!.Enabled = _nextPage!.Enabled = false;
        try
        {
            var result = await Task.Run(async () =>
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
                        return (Bitmap: image, Page: _page, Count: _pdf.PageCount);
                    }
                    catch { image.Recycle(); image.Dispose(); throw; }
                }
                finally { _pdfGate.Release(); }
            });
            if (_destroyed) { result.Bitmap.Recycle(); result.Bitmap.Dispose(); return; }
            _pageImage!.SetImageBitmap(result.Bitmap);
            _pageBitmap?.Recycle();
            _pageBitmap?.Dispose();
            _pageBitmap = result.Bitmap;
            _pageCount = result.Count;
            _status.Text = $"{_content!.Name} — {result.Page + 1} / {result.Count}";
        }
        catch (Exception ex) { ShowError(ex); }
        finally
        {
            _pdfRendering = false;
            if (!_destroyed)
            {
                _previousPage.Enabled = _page > 0;
                _nextPage.Enabled = _page + 1 < _pageCount;
            }
        }
    }

    private void ShowError(Exception ex)
    {
        if (!_destroyed) RunOnUiThread(() => { if (!_destroyed) _status.Text = ex.Message; });
    }

    protected override void OnPause()
    {
        _resumed = false;
        if (_prepared && _player is not null) RunMediaAction(() =>
        {
            if (_player.IsPlaying) { _player.Pause(); _play.Text = "再生"; }
        });
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
        if (_surfaceCallbacks is not null) _videoSurface?.Holder?.RemoveCallback(_surfaceCallbacks);
        _player?.Release();
        _player?.Dispose();
        _media?.Dispose();
        _pageImage?.SetImageBitmap(null);
        _pageBitmap?.Recycle();
        _pageBitmap?.Dispose();
        _pageBitmap = null;
        // Native PDF rendering is not cancellable. Waiting for it on the main
        // thread would freeze closing/navigation; release resources off-thread.
        _ = Task.Run(DisposePdfAsync);
        _surfaceCallbacks?.Dispose();
        _positionHandler?.Dispose();
        base.OnDestroy();
    }

    private async Task DisposePdfAsync()
    {
        await _pdfGate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (OperatingSystem.IsAndroidVersionAtLeast(26))
            {
                try { _pdf?.Close(); }
                finally
                {
                    try { _pdf?.Dispose(); }
                    finally
                    {
                        try { _pdfDescriptor?.Dispose(); }
                        finally { _pdf = null; _pdfDescriptor = null; }
                    }
                }
            }
        }
        catch (Exception) { Android.Util.Log.Warn("CistaNAS", "PDF resource cleanup failed."); }
        finally { _pdfGate.Release(); }
    }

    private sealed class SurfaceCallbacks(StreamingViewerActivity activity) : Java.Lang.Object, ISurfaceHolderCallback
    {
        private bool _preparing;
        public void SurfaceCreated(ISurfaceHolder holder)
        {
            activity.RunMediaAction(() =>
            {
                activity._player?.SetDisplay(holder);
                if (!_preparing) { _preparing = true; activity._player?.PrepareAsync(); }
            });
        }
        public void SurfaceChanged(ISurfaceHolder holder, Android.Graphics.Format format, int width, int height) { }
        public void SurfaceDestroyed(ISurfaceHolder holder)
        {
            activity.RunMediaAction(() =>
            {
                if (activity._prepared && activity._player?.IsPlaying == true) activity._player.Pause();
                activity._player?.SetDisplay(null);
            });
        }
    }
}
