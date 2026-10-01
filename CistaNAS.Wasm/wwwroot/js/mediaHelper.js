// Media previews own their requests, decoder buffers and object URLs until
// replaced or closed. Plaintext is never written to a client file cache.
(() => {
    const previews = new WeakMap();
    const active = new Set();
    const maxFallbackBytes = 64 * 1024 * 1024;

    function abortError() { return new DOMException("Preview cancelled", "AbortError"); }
    function clearElement(element) {
        if (element.tagName === "VIDEO" || element.tagName === "AUDIO") element.pause();
        element.removeAttribute("src");
        if (element.tagName === "VIDEO" || element.tagName === "AUDIO") element.load();
    }
    function stop(operation) {
        if (!operation || operation.controller.signal.aborted) return;
        operation.controller.abort();
        active.delete(operation);
        if (previews.get(operation.element) === operation) {
            previews.delete(operation.element);
            clearElement(operation.element);
        }
        for (const url of operation.urls) URL.revokeObjectURL(url);
        operation.urls.clear();
    }
    function begin(element) {
        stop(previews.get(element));
        const operation = {
            element, controller: new AbortController(), urls: new Set(),
            token: sessionStorage.getItem("cista_jwt")
        };
        previews.set(element, operation);
        active.add(operation);
        return operation;
    }
    function ensureCurrent(operation) {
        if (operation.controller.signal.aborted || !operation.element.isConnected
            || previews.get(operation.element) !== operation
            || sessionStorage.getItem("cista_jwt") !== operation.token) {
            stop(operation);
            throw abortError();
        }
    }
    function setObjectSource(operation, value) {
        ensureCurrent(operation);
        const url = URL.createObjectURL(value);
        operation.urls.add(url);
        operation.element.src = url;
    }
    function waitForEvent(target, success, failure, signal, start, timeout) {
        return new Promise((resolve, reject) => {
            let timer;
            const cleanup = () => {
                target.removeEventListener(success, onSuccess);
                target.removeEventListener(failure, onFailure);
                signal.removeEventListener("abort", onAbort);
                clearTimeout(timer);
            };
            const onSuccess = () => { cleanup(); resolve(); };
            const onFailure = () => { cleanup(); reject(new Error("Media decoder failed")); };
            const onAbort = () => { cleanup(); reject(abortError()); };
            target.addEventListener(success, onSuccess);
            target.addEventListener(failure, onFailure);
            signal.addEventListener("abort", onAbort, { once: true });
            if (signal.aborted) { onAbort(); return; }
            if (timeout) timer = setTimeout(() => { cleanup(); reject(new Error("MediaSource sourceopen timeout")); }, timeout);
            try { if (start) start(); } catch (error) { cleanup(); reject(error); }
        });
    }
    function base64ToUint8(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes;
    }
    async function fallbackBlob(operation, mimeType, getNextChunk, onProgress) {
        const chunks = [];
        let index = 0, size = 0;
        try {
            while (true) {
                ensureCurrent(operation);
                const chunk = await getNextChunk();
                ensureCurrent(operation);
                if (chunk === null) break;
                const bytes = base64ToUint8(chunk);
                chunks.push(bytes);
                size += bytes.length;
                if (size > maxFallbackBytes)
                    throw new Error("この形式のプレビューは64 MiB以下のファイルに対応しています。");
                if (onProgress) onProgress(++index, -1);
            }
            setObjectSource(operation, new Blob(chunks, { type: mimeType }));
            if (operation.element.tagName === "VIDEO" || operation.element.tagName === "AUDIO") {
                operation.element.load();
                // Playback may wait for data/metadata. It must not hold up the
                // producer or cancellation of this preview.
                try { operation.element.play().catch(() => {}); } catch { }
                ensureCurrent(operation);
            }
        } finally {
            for (const bytes of chunks) bytes.fill(0);
        }
    }
    async function stream(operation, mimeType, getNextChunk, onProgress) {
        try {
            ensureCurrent(operation);
            if (!("MediaSource" in window))
                throw new Error("このブラウザは MediaSource Extensions に対応していません。");
            const codecsMap = {
                "video/mp4": ['video/mp4; codecs="avc1.42E01E,mp4a.40.2"', 'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="mp4a.40.2"', "video/mp4"],
                "video/webm": ['video/webm; codecs="vp8,vorbis"', 'video/webm; codecs="vp9,opus"', "video/webm"],
                "audio/webm": ['audio/webm; codecs="opus"', "audio/webm"]
            };
            const mseMime = (codecsMap[mimeType] || [mimeType]).find(type => MediaSource.isTypeSupported(type));
            if (!mseMime) return await fallbackBlob(operation, mimeType, getNextChunk, onProgress);

            const source = new MediaSource();
            await waitForEvent(source, "sourceopen", "error", operation.controller.signal,
                () => setObjectSource(operation, source), 5000);
            ensureCurrent(operation);
            const buffer = source.addSourceBuffer(mseMime);
            buffer.mode = "segments";
            let index = 0;
            while (true) {
                ensureCurrent(operation);
                const chunk = await getNextChunk();
                ensureCurrent(operation);
                if (chunk === null) break;
                const bytes = base64ToUint8(chunk);
                try {
                    if (buffer.updating)
                        await waitForEvent(buffer, "updateend", "error", operation.controller.signal);
                    ensureCurrent(operation);
                    await waitForEvent(buffer, "updateend", "error", operation.controller.signal,
                        () => buffer.appendBuffer(bytes));
                    ensureCurrent(operation);
                } finally { bytes.fill(0); }
                index++;
                if (onProgress) onProgress(index, -1);
                if (index === 1 && operation.element.paused) {
                    try { operation.element.play().catch(() => {}); } catch { }
                    ensureCurrent(operation);
                }
            }
            if (source.readyState === "open") source.endOfStream();
        } catch (error) {
            stop(operation);
            throw error;
        }
    }

    // Blazor may remove a player before its pending JS interop call completes.
    new MutationObserver(() => {
        for (const operation of active)
            if (!operation.element.isConnected) stop(operation);
    }).observe(document.documentElement, { childList: true, subtree: true });

    window.cistaMedia = {
        revokeBlobUrl(url) { if (url?.startsWith("blob:")) URL.revokeObjectURL(url); },
        stop(elementId) {
            for (const operation of active)
                if (operation.element.id === elementId) stop(operation);
        },
        stopAll() { for (const operation of active) stop(operation); },
        async getStreamUrl(apiBase, volumeName, fileName, jwtToken, signal) {
            const response = await fetch(apiBase + "/api/v1/stream/token", {
                method: "POST", signal, cache: "no-store",
                headers: { "Authorization": "Bearer " + jwtToken, "Content-Type": "application/json" },
                body: JSON.stringify({ volumeName, fileName })
            });
            if (!response.ok) throw new Error("stream token failed: " + response.status);
            const data = await response.json();
            return apiBase + "/api/v1/stream/" + encodeURIComponent(volumeName) + "/"
                + encodeURIComponent(fileName) + "?token=" + encodeURIComponent(data.token);
        },
        async setStreamUrl(elementId, apiBase, volumeName, fileName) {
            const element = document.getElementById(elementId);
            if (!element) throw abortError();
            const operation = begin(element);
            try {
                if (!operation.token) throw new Error("ログインしてください。");
                const url = await this.getStreamUrl(apiBase, volumeName, fileName,
                    operation.token, operation.controller.signal);
                ensureCurrent(operation);
                element.src = url;
                if (element.tagName === "VIDEO" || element.tagName === "AUDIO") element.load();
            } catch (error) { stop(operation); throw error; }
        },
        async streamE2ee(element, mimeType, getNextChunk, onProgress) {
            return await stream(begin(element), mimeType, getNextChunk, onProgress);
        },
        async streamE2eeDirect(options) {
            const element = document.getElementById(options.elementId);
            if (!element) throw abortError();
            const operation = begin(element);
            let index = 0;
            const getNextChunk = async () => {
                ensureCurrent(operation);
                if (options.jwtToken && options.jwtToken !== operation.token) throw abortError();
                if (!operation.token) throw new Error("ログインしてください。");
                if (index >= options.chunkCount) return null;
                const response = await fetch(options.apiUrl + "/api/v1/e2ee/" + encodeURIComponent(options.volumeName)
                    + "/download-chunk/" + encodeURIComponent(options.fileId) + "/" + index, {
                    signal: operation.controller.signal, cache: "no-store",
                    headers: { "Authorization": "Bearer " + operation.token }
                });
                ensureCurrent(operation);
                if (!response.ok) throw new Error("chunk download failed: " + response.status + " idx=" + index);
                const encrypted = new Uint8Array(await response.arrayBuffer());
                ensureCurrent(operation);
                const revision = Number(response.headers.get("X-Chunk-Revision") || "0");
                if (!Number.isSafeInteger(revision) || revision < 0) throw new Error("Invalid chunk revision");
                let binary = "";
                for (const byte of encrypted) binary += String.fromCharCode(byte);
                const plaintext = await window.cistaE2ee.decryptChunk(btoa(binary), options.masterKeyHandle,
                    index, options.fileSaltBase64, revision);
                ensureCurrent(operation);
                index++;
                try { options.dotNetRef?.invokeMethod("OnProgress", index); } catch { }
                return plaintext;
            };
            return await stream(operation, options.mimeType, getNextChunk);
        }
    };
})();
