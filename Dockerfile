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
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "CistaNAS.Web.dll"]
