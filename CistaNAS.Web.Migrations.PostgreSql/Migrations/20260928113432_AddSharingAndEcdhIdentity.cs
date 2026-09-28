using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CistaNAS.Web.Migrations.PostgreSql.Migrations
{
    /// <inheritdoc />
    public partial class AddSharingAndEcdhIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "EcdhDerivationVersion",
                table: "Users",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<byte[]>(
                name: "EcdhIdentitySalt",
                table: "Users",
                type: "bytea",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SharingEnabled",
                table: "Users",
                type: "boolean",
                nullable: false,
                defaultValue: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EcdhDerivationVersion",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "EcdhIdentitySalt",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "SharingEnabled",
                table: "Users");
        }
    }
}
