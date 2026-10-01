using Microsoft.Playwright;

namespace CistaNAS.PlaywrightTests;

[Collection("Playwright")]
public sealed class MediaPreviewLifecycleTests(PlaywrightWebAppFixture fixture)
{
    [Theory]
    [InlineData("close")]
    [InlineData("remove")]
    [InlineData("logout")]
    [InlineData("replace")]
    public async Task PendingChunk_CannotRestoreClosedOrSupersededPreview(string action)
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/volumes");
        await page.WaitForFunctionAsync("() => !!window.cistaMedia");
        bool safe = await page.EvaluateAsync<bool>("""
            async action => {
                window.MediaSource = { isTypeSupported: () => false };
                const element = document.createElement('img');
                element.id = 'lifecycle-media';
                document.body.appendChild(element);
                const originalFetch = window.fetch;
                const originalDecrypt = window.cistaE2ee.decryptChunk;
                let release, started;
                const pending = new Promise(resolve => release = resolve);
                const entered = new Promise(resolve => started = resolve);
                let fetches = 0, decryptions = 0;
                window.fetch = async () => {
                    fetches++;
                    started();
                    await pending; // Deliberately ignore AbortSignal.
                    return new Response(new Uint8Array(33), { status: 200 });
                };
                window.cistaE2ee.decryptChunk = async () => { decryptions++; return btoa('old'); };
                const stream = window.cistaMedia.streamE2eeDirect({
                    elementId: element.id, mimeType: 'image/png', apiUrl: location.origin,
                    jwtToken: sessionStorage.getItem('cista_jwt'), volumeName: 'v', fileId: 'f',
                    chunkCount: 2, masterKeyHandle: 'key', fileSaltBase64: btoa('salt')
                }).then(() => null, error => error.name);
                let replacementUrl = null;
                try {
                    await entered;
                    if (action === 'close') {
                        if (!window.cistaMedia.stop) return false;
                        window.cistaMedia.stop(element.id);
                    }
                    if (action === 'remove') {
                        element.remove();
                        await new Promise(resolve => setTimeout(resolve, 0));
                    }
                    if (action === 'logout') sessionStorage.setItem('cista_jwt', 'different-session');
                    if (action === 'replace') {
                        let first = true;
                        await window.cistaMedia.streamE2ee(element, 'image/png', async () => {
                            if (!first) return null;
                            first = false;
                            return btoa('new');
                        });
                        replacementUrl = element.getAttribute('src');
                    }
                    release();
                    await stream;
                    return fetches === 1 && decryptions === 0
                        && (action === 'replace' ? element.getAttribute('src') === replacementUrl
                            : !element.hasAttribute('src'));
                } finally {
                    release();
                    await stream;
                    window.cistaMedia.stop?.(element.id);
                    element.remove();
                    window.fetch = originalFetch;
                    window.cistaE2ee.decryptChunk = originalDecrypt;
                }
            }
            """, action).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(safe, $"The {action} action allowed stale media reads or publication.");
    }

    [Fact]
    public async Task ReplacingAndClosingFallbackPreview_ReleasesEveryBlobUrl()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/volumes");
        await page.WaitForFunctionAsync("() => !!window.cistaMedia");
        bool released = await page.EvaluateAsync<bool>("""
            async () => {
                window.MediaSource = { isTypeSupported: () => false };
                const element = document.createElement('img');
                element.id = 'blob-media';
                document.body.appendChild(element);
                const created = [], revoked = [];
                const create = URL.createObjectURL, revoke = URL.revokeObjectURL;
                URL.createObjectURL = blob => { const url = create(blob); created.push(url); return url; };
                URL.revokeObjectURL = url => { revoked.push(url); revoke(url); };
                try {
                    for (let i = 0; i < 3; i++) {
                        let first = true;
                        await window.cistaMedia.streamE2ee(element, 'image/png', async () => {
                            if (!first) return null;
                            first = false;
                            return btoa('secret');
                        });
                    }
                    window.cistaMedia.stop?.(element.id);
                    return created.length === 3 && created.every(url => revoked.includes(url))
                        && !element.hasAttribute('src');
                } finally {
                    created.forEach(revoke);
                    URL.createObjectURL = create;
                    URL.revokeObjectURL = revoke;
                    element.remove();
                }
            }
            """).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(released, "Decrypted Blob URLs remained registered after replacement/close.");
    }

    [Fact]
    public async Task FailedMediaSourceInitialization_ReleasesItsObjectUrl()
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/volumes");
        await page.WaitForFunctionAsync("() => !!window.cistaMedia");
        bool released = await page.EvaluateAsync<bool>("""
            async () => {
                window.MediaSource = class extends EventTarget {
                    static isTypeSupported() { return true; }
                    constructor() { super(); setTimeout(() => this.dispatchEvent(new Event('sourceopen')), 0); }
                    addSourceBuffer() { throw new Error('decoder initialization failed'); }
                };
                const element = document.createElement('video');
                element.id = 'failed-media';
                document.body.appendChild(element);
                const create = URL.createObjectURL, revoke = URL.revokeObjectURL;
                let revoked = false;
                URL.createObjectURL = () => 'blob:failed-media';
                URL.revokeObjectURL = url => { if (url === 'blob:failed-media') revoked = true; };
                try {
                    await window.cistaMedia.streamE2ee(element, 'video/mp4', async () => null).catch(() => {});
                    return revoked && !element.hasAttribute('src');
                } finally {
                    URL.createObjectURL = create;
                    URL.revokeObjectURL = revoke;
                    element.remove();
                }
            }
            """).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(released, "Failed MediaSource initialization retained an object URL.");
    }

    [Theory]
    [InlineData("sourceopen")]
    [InlineData("append")]
    [InlineData("complete")]
    [InlineData("playpending")]
    public async Task DecoderCompletionOrCancellation_CleansListenersAndPlaintext(string stage)
    {
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync(fixture.BaseUrl + "/volumes");
        await page.WaitForFunctionAsync("() => !!window.cistaMedia");
        bool cleaned = await page.EvaluateAsync<bool>("""
            async stage => {
                let source, buffer, reached;
                const entered = new Promise(resolve => reached = resolve);
                const targets = [], plaintext = [];
                class TrackedTarget extends EventTarget {
                    constructor() { super(); this.listeners = new Map(); targets.push(this); }
                    addEventListener(type, listener, options) {
                        if (!this.listeners.has(type)) this.listeners.set(type, new Set());
                        this.listeners.get(type).add(listener);
                        super.addEventListener(type, listener, options);
                    }
                    removeEventListener(type, listener) {
                        this.listeners.get(type)?.delete(listener);
                        super.removeEventListener(type, listener);
                    }
                }
                window.MediaSource = class extends TrackedTarget {
                    static isTypeSupported() { return true; }
                    constructor() {
                        super(); source = this; this.readyState = 'open';
                        setTimeout(() => {
                            if (stage === 'sourceopen') reached();
                            else this.dispatchEvent(new Event('sourceopen'));
                        }, 0);
                    }
                    addSourceBuffer() {
                        buffer = new TrackedTarget();
                        buffer.appendBuffer = bytes => {
                            plaintext.push(bytes);
                            if (stage === 'append') reached();
                            else setTimeout(() => buffer.dispatchEvent(new Event('updateend')), 0);
                        };
                        return buffer;
                    }
                    endOfStream() { this.readyState = 'ended'; }
                };
                const element = document.createElement('video');
                element.id = 'decoder-media';
                element.play = () => stage === 'playpending' ? new Promise(() => {}) : Promise.resolve();
                element.load = () => {};
                document.body.appendChild(element);
                const create = URL.createObjectURL, revoke = URL.revokeObjectURL;
                let revoked = false;
                URL.createObjectURL = () => 'blob:decoder-media';
                URL.revokeObjectURL = url => { if (url === 'blob:decoder-media') revoked = true; };
                let index = 0;
                const running = window.cistaMedia.streamE2ee(element, 'video/mp4', async () =>
                    index++ < 3 ? btoa('plaintext') : null).then(() => null, error => error.name);
                try {
                    if (stage !== 'complete' && stage !== 'playpending') {
                        await entered;
                        window.cistaMedia.stop(element.id);
                    }
                    const error = await running;
                    window.cistaMedia.stop(element.id);
                    return (stage === 'complete' || stage === 'playpending'
                        ? error === null && plaintext.length === 3 : error === 'AbortError')
                        && plaintext.every(bytes => bytes.every(value => value === 0))
                        && targets.every(target => [...target.listeners.values()].every(set => set.size === 0))
                        && revoked && !element.hasAttribute('src');
                } finally {
                    window.cistaMedia.stop?.(element.id);
                    URL.createObjectURL = create;
                    URL.revokeObjectURL = revoke;
                    element.remove();
                }
            }
            """, stage).WaitAsync(TimeSpan.FromSeconds(15));
        Assert.True(cleaned, $"Decoder {stage} retained listeners, URLs or plaintext buffers.");
    }
}

public partial class E2eeBrowserTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task EncryptedImagePreview_CloseOrLogoutReleasesDecodedContent(bool logout)
    {
        string volume = await CreateE2eeVolumeAsync();
        await using var context = await fixture.CreateAuthenticatedContextAsync();
        var page = await context.NewPageAsync();
        await page.GotoAsync($"{fixture.BaseUrl}/files/{volume}");
        await page.Locator("input[type=password]").FillAsync(PlaywrightWebAppFixture.Password);
        await page.Locator("input[type=password]").PressAsync("Tab");
        await page.GetByRole(AriaRole.Button, new() { Name = "ロック解除", Exact = true }).ClickAsync();
        await page.WaitForFunctionAsync("() => document.body.textContent.includes('クライアント側暗号化有効')");
        await page.SetInputFilesAsync("input[type=file]", new FilePayload
        {
            Name = "preview.png", MimeType = "image/png",
            Buffer = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=")
        });
        await page.GetByRole(AriaRole.Button, new() { Name = "プレビュー", Exact = true }).WaitForAsync();
        await page.EvaluateAsync("""
            () => {
                window.revokedMedia = [];
                const revoke = URL.revokeObjectURL;
                URL.revokeObjectURL = url => { window.revokedMedia.push(url); revoke(url); };
            }
            """);
        await page.GetByRole(AriaRole.Button, new() { Name = "プレビュー", Exact = true }).ClickAsync();
        await page.WaitForFunctionAsync("() => { const img = document.querySelector('.media-preview img'); return img?.complete && img.naturalWidth === 1; }");
        string url = await page.Locator(".media-preview img").GetAttributeAsync("src") ?? "";
        Assert.StartsWith("blob:", url);
        // The preview covers the header's pointer target; keyboard activation
        // exercises logout without first closing and releasing the preview.
        if (logout) await page.GetByRole(AriaRole.Button, new() { Name = "ログアウト", Exact = true }).PressAsync("Enter");
        else await page.Locator(".preview-header button").ClickAsync();
        await page.WaitForFunctionAsync("url => window.revokedMedia.includes(url) && !document.querySelector('.media-preview')", url);
    }
}
