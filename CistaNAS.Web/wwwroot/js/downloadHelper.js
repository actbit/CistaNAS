// CistaNAS — ファイルダウンロードヘルパー
window.cistaDownload = function (fileName, base64Data, mimeType) {
    const bytes = atob(base64Data);
    const buf = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) buf[i] = bytes.charCodeAt(i);
    const blob = new Blob([buf], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

/**
 * E2EE メディア用: 複数の base64 チャンクを結合して Blob URL を生成。
 */
window.cistaCreateMediaBlobUrl = function (base64Chunks, mimeType) {
    const arrays = base64Chunks.map(function (b64) {
        const bytes = atob(b64);
        const buf = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) buf[i] = bytes.charCodeAt(i);
        return buf;
    });
    const blob = new Blob(arrays, { type: mimeType });
    return URL.createObjectURL(blob);
};
