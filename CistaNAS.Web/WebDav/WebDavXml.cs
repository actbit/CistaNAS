using System.Xml;

namespace CistaNAS.Web.WebDav;

/// <summary>
/// WebDAV XML の生成・解析ユーティリティ。
/// </summary>
public static class WebDavXml
{
    private const string DavNs = "DAV:";

    /// <summary>PROPFIND レスポンスの multistatus XML を生成する。</summary>
    public static string BuildMultiStatus(IReadOnlyList<WebDavResource> resources, string baseUrl)
    {
        using var sw = new StringWriter();
        using var xw = XmlWriter.Create(sw, new XmlWriterSettings
        {
            Indent = false,
            Encoding = System.Text.Encoding.UTF8,
            OmitXmlDeclaration = false,
        });

        xw.WriteStartDocument();
        xw.WriteStartElement("D", "multistatus", DavNs);

        foreach (var r in resources)
        {
            xw.WriteStartElement("response", DavNs);

            // href
            xw.WriteElementString("href", DavNs, BuildHref(baseUrl, r.Path, r.IsCollection));

            // propstat
            xw.WriteStartElement("propstat", DavNs);

            xw.WriteStartElement("prop", DavNs);

            // resourcetype
            xw.WriteStartElement("resourcetype", DavNs);
            if (r.IsCollection)
                xw.WriteStartElement("collection", DavNs);
            xw.WriteEndElement(); // resourcetype

            // displayname
            string name = r.Path.TrimEnd('/').Split('/').Last();
            if (string.IsNullOrEmpty(name)) name = "/";
            xw.WriteElementString("displayname", DavNs, name);

            // getcontentlength
            if (!r.IsCollection)
                xw.WriteElementString("getcontentlength", DavNs, r.Size.ToString());

            // getlastmodified (RFC 1123)
            if (r.LastModified.HasValue)
                xw.WriteElementString("getlastmodified", DavNs, r.LastModified.Value.ToString("R"));

            // getcontenttype
            if (!r.IsCollection)
                xw.WriteElementString("getcontenttype", DavNs, "application/octet-stream");

            xw.WriteEndElement(); // prop

            xw.WriteElementString("status", DavNs, "HTTP/1.1 200 OK");
            xw.WriteEndElement(); // propstat

            xw.WriteEndElement(); // response
        }

        xw.WriteEndElement(); // multistatus
        xw.WriteEndDocument();
        xw.Flush();
        return sw.ToString();
    }

    /// <summary>PROPFIND リクエストの Depth ヘッダ値をパース。規定は infinity。</summary>
    public static int ParseDepth(string? depth) => depth switch
    {
        "0" => 0,
        "1" => 1,
        _ => -1, // infinity
    };

    private static string BuildHref(string baseUrl, string path, bool isCollection)
    {
        // baseUrl = "/dav/volume", path = "" or "dir/file.txt"
        string href = string.IsNullOrEmpty(path) ? baseUrl : $"{baseUrl}/{Uri.EscapeDataString(path).Replace("%2F", "/")}";
        if (isCollection && !href.EndsWith('/')) href += '/';
        return href;
    }
}

/// <summary>WebDAV リソースのメタデータ。</summary>
public sealed class WebDavResource
{
    public required string Path { get; set; }
    public bool IsCollection { get; set; }
    public long Size { get; set; }
    public DateTimeOffset? LastModified { get; set; }
}
