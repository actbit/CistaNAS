using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace CistaNAS.Web.Migrations.Sqlite.Migrations
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
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<byte[]>(
                name: "EcdhIdentitySalt",
                table: "Users",
                type: "BLOB",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SharingEnabled",
                table: "Users",
                type: "INTEGER",
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
