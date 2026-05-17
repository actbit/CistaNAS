namespace CistaNAS.Web.Models;

/// <summary>ボリューム内のファイルメタデータ。</summary>
public sealed class FileMetadata
{
    public required string Name { get; set; }
    public long Offset { get; set; }
    public long Length { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset ModifiedAt { get; set; }
}

public sealed record ListFilesResponse(IReadOnlyList<FileMetadata> Files);
public sealed record FileUploadRequest(string VolumeName, string FileName, Stream Content, long ContentLength);
public sealed record FileDownloadResponse(Stream Stream, string FileName, long Length);

/// <summary>ファイル操作の業務エラー。</summary>
public sealed class FileServiceException(string message) : Exception(message);
