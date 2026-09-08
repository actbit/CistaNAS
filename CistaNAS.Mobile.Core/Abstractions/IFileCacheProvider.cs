namespace CistaNAS.Mobile.Core.Abstractions;

/// <summary>外部アプリへ渡す一時ファイルのキャッシュ場所を提供する。</summary>
public interface IFileCacheProvider
{
    /// <summary>キャッシュディレクトリ内に書き込み用ファイルを作成する Stream を開く。</summary>
    Stream OpenWrite(string fileName);

    /// <summary>キャッシュ済みファイルのフルパスを取得する (外部委譲用)。</summary>
    string GetPath(string fileName);

    /// <summary>キャッシュディレクトリを掃除する。</summary>
    void Clear();
}
