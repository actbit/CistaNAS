FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY CistaNAS.slnx .
COPY CistaNAS.Web/CistaNAS.Web.csproj CistaNAS.Web/
COPY CistaNAS.ServiceDefaults/CistaNAS.ServiceDefaults.csproj CistaNAS.ServiceDefaults/
RUN dotnet restore CistaNAS.Web/CistaNAS.Web.csproj
COPY CistaNAS.Web/ CistaNAS.Web/
COPY CistaNAS.ServiceDefaults/ CistaNAS.ServiceDefaults/
RUN dotnet publish CistaNAS.Web/CistaNAS.Web.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

# 非 root ユーザーで実行（セキュリティ向上）
RUN adduser --disabled-password --gecos "" --home /nonexistent appuser && \
    mkdir -p /app/data && \
    chown appuser /app/data
USER appuser

EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1
ENTRYPOINT ["dotnet", "CistaNAS.Web.dll"]
