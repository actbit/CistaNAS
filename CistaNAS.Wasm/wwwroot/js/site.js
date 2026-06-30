// CSP の script-src 'unsafe-inline' を削除するため、Blazor テンプレート由来の
// インライン onclick ハンドラ（NavMenu の navbar クローズ処理）を外部スクリプトへ移行。
// NavMenu.razor の @onclick → IJSRuntime 経由でここを呼ぶ。
window.cista = window.cista || {};
window.cista.closeNavbar = function () {
    const toggler = document.querySelector('.navbar-toggler');
    if (toggler) toggler.click();
};
// CSP の script-src 'unsafe-eval' を許可しない構成で eval がブロックされるため、
// Files.razor の DownloadFile から window.open の代わりに使用（eval 不要）。
// Blazor の JS interop 経由の window.open は「ユーザー操作文脈」を失い popup blocker に
// ブロックされやすいため、<a target=_blank> のプログラム的クリックで開く。
window.cista.openUrl = function (url) {
    const a = document.createElement("a");
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
};
