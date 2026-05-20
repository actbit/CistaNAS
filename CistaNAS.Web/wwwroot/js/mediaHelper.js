// CistaNAS — メディアプレビューヘルパー
// 通常ボリューム: 短命トークン付きURL → ネイティブストリーミング
// E2EE ボリューム: MediaSource Extensions でプログレッシブ復号再生

window.cistaMedia = {

    // ---- 共通 ----

    /**
     * Blob URL を解放する。
     */
    revokeBlobUrl(url) {
        if (url && url.startsWith("blob:")) {
            URL.revokeObjectURL(url);
        }
    },

    // ---- 通常ボリューム: ストリーミング ----

    /**
     * ストリーミングトークンを発行し、ストリーミングURLを返す。
     * <video> / <audio> / <img> の src に直接セットできる。
     * Range リクエスト対応なのでブラウザが自動でシーク・バッファリングする。
     */
    async getStreamUrl(apiBase, volumeName, fileName, jwtToken) {
        const resp = await fetch(apiBase + "/api/v1/stream/token", {
            method: "POST",
            headers: {
                "Authorization": "Bearer " + jwtToken,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ volumeName, fileName })
        });
        if (!resp.ok) throw new Error("stream token failed: " + resp.status);
        const data = await resp.json();
        const encoded = encodeURIComponent(fileName);
        return apiBase + "/api/v1/stream/" + encodeURIComponent(volumeName) + "/" + encoded + "?token=" + data.token;
    },

    // ---- E2EE ボリューム: プログレッシブ復号 → MediaSource ----

    /**
     * E2EE メディアをプログレッシブに復号・再生する。
     * Blazor からチャンク取得コールバックを通じて復号済みデータを順次受け取る。
     *
     * @param {HTMLVideoElement|HTMLAudioElement} element - メディア要素
     * @param {string} mimeType - MIMEタイプ (例: "video/mp4", "audio/mpeg")
     * @param {function} getNextChunk - async () => { base64: string } | null
     *   呼ばれるたびに次の復号済みチャンク(base64)を返す。nullで終了。
     * @param {function} onProgress - (loaded, total) => void (省略可)
     * @returns {Promise} 再生終了またはエラーで解決
     */
    async streamE2ee(element, mimeType, getNextChunk, onProgress) {
        // MediaSource が使えるか確認
        if (!("MediaSource" in window)) {
            throw new Error("このブラウザは MediaSource Extensions に対応していません。");
        }

        // MSE で扱える MIME を判定
        // ブラウザが mp4 を video/mp4; codecs=... でしか受け付けない場合があるため、
        // 複数パターンを試す
        const codecsMap = {
            "video/mp4": ['video/mp4; codecs="avc1.42E01E,mp4a.40.2"', 'video/mp4; codecs="avc1.42E01E"', 'video/mp4; codecs="mp4a.40.2"', "video/mp4"],
            "video/webm": ['video/webm; codecs="vp8,vorbis"', 'video/webm; codecs="vp9,opus"', "video/webm"],
            "audio/mpeg": ["audio/mpeg"],
            "audio/mp4": ["audio/mp4"],
            "audio/ogg": ["audio/ogg"],
            "audio/wav": ["audio/wav"],
            "audio/flac": ["audio/flac"],
            "audio/webm": ["audio/webm; codecs=\"opus\"", "audio/webm"],
        };

        let mseMime = mimeType;
        const candidates = codecsMap[mimeType] || [mimeType];
        for (const c of candidates) {
            if (MediaSource.isTypeSupported(c)) {
                mseMime = c;
                break;
            }
        }

        // MSE非対応形式なら Blob にフォールバック
        if (!MediaSource.isTypeSupported(mseMime)) {
            return await fallbackBlob(element, mimeType, getNextChunk, onProgress);
        }

        const mediaSource = new MediaSource();
        element.src = URL.createObjectURL(mediaSource);

        await new Promise((resolve, reject) => {
            mediaSource.addEventListener("sourceopen", resolve, { once: true });
            setTimeout(() => reject(new Error("MediaSource sourceopen timeout")), 5000);
        });

        const sourceBuffer = mediaSource.addSourceBuffer(mseMime);
        sourceBuffer.mode = "segments";

        try {
            let chunkIndex = 0;
            while (true) {
                const chunk = await getNextChunk();
                if (chunk === null) break;

                const bytes = base64ToUint8(chunk);
                // SourceBuffer への追加が完了するまで待機
                await appendToBuffer(sourceBuffer, bytes);

                chunkIndex++;
                if (onProgress) onProgress(chunkIndex, -1);

                // 最初のチャンクが入ったら自動再生
                if (chunkIndex === 1 && element.paused) {
                    try { await element.play(); } catch {}
                }
            }

            // 全チャンク追加完了
            if (mediaSource.readyState === "open") {
                mediaSource.endOfStream();
            }
        } catch (err) {
            // MSE対応していてもコンテナ形式の問題で失敗することがある
            // その場合は Blob にフォールバック
            console.warn("MSE failed, falling back to Blob:", err);
            element.pause();
            element.removeAttribute("src");
            element.load();
            // 最初からBlobでやり直し
            return await fallbackBlob(element, mimeType, getNextChunk, onProgress, true);
        }
    },

    /**
     * base64 → Uint8Array
     */
    base64ToUint8(base64) {
        return base64ToUint8(base64);
    }
};

// ---- 内部ヘルパー ----

function base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function appendToBuffer(sourceBuffer, data) {
    return new Promise((resolve, reject) => {
        if (sourceBuffer.updating) {
            sourceBuffer.addEventListener("updateend", () => {
                appendToBuffer(sourceBuffer, data).then(resolve).catch(reject);
            }, { once: true });
            return;
        }
        try {
            sourceBuffer.addEventListener("updateend", resolve, { once: true });
            sourceBuffer.addEventListener("error", reject, { once: true });
            sourceBuffer.appendBuffer(data);
        } catch (e) {
            reject(e);
        }
    });
}

/**
 * Blob フォールバック: 全チャンクを結合してから再生。
 * MSE非対応形式や、MSEが失敗した場合のフォールバック。
 */
async function fallbackBlob(element, mimeType, getNextChunk, onProgress, resetGenerator) {
    const chunks = [];
    let index = 0;

    // ジェネレーターをリセットできないので、残りのチャンクだけ收集
    // resetGenerator=true の場合、getNextChunk は最初からやり直せないため
    // すでに消費したチャンクは失われている。このパスでは新しいジェネレーターが必要。
    // Blazor 側で再ダウンロード → 再復号して渡す設計。

    while (true) {
        const chunk = await getNextChunk();
        if (chunk === null) break;
        chunks.push(base64ToUint8(chunk));
        index++;
        if (onProgress) onProgress(index, -1);
    }

    const blob = new Blob(chunks, { type: mimeType });
    const url = URL.createObjectURL(blob);
    element.src = url;
    element.load();
    try { await element.play(); } catch {}
}
