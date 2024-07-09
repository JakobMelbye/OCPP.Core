using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace OCPP.Core.Database.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ChargePoint",
                columns: table => new
                {
                    ChargePointId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Name = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    Comment = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    Username = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    Password = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    ClientCertThumb = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ChargePoint", x => x.ChargePointId);
                });

            migrationBuilder.CreateTable(
                name: "ChargeTags",
                columns: table => new
                {
                    TagId = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: false),
                    TagName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                    ParentTagId = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    ExpiryDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                    Blocked = table.Column<bool>(type: "bit", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ChargeKeys", x => x.TagId);
                });

            migrationBuilder.CreateTable(
                name: "MessageLog",
                columns: table => new
                {
                    LogId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    LogTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    ChargePointId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ConnectorId = table.Column<int>(type: "int", nullable: true),
                    Message = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Result = table.Column<string>(type: "nvarchar(max)", nullable: true),
                    ErrorCode = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MessageLog", x => x.LogId);
                });

            migrationBuilder.CreateTable(
                name: "ConnectorStatus",
                columns: table => new
                {
                    ChargePointId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ConnectorId = table.Column<int>(type: "int", nullable: false),
                    ConnectorName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    LastStatus = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    LastStatusTime = table.Column<DateTime>(type: "datetime2", nullable: true),
                    LastMeter = table.Column<double>(type: "float", nullable: true),
                    LastMeterTime = table.Column<DateTime>(type: "datetime2", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConnectorStatus", x => new { x.ChargePointId, x.ConnectorId });
                    table.ForeignKey(
                        name: "FK_ConnectorStatus_ChargePoint_ChargePointId",
                        column: x => x.ChargePointId,
                        principalTable: "ChargePoint",
                        principalColumn: "ChargePointId",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Transactions",
                columns: table => new
                {
                    TransactionId = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    Uid = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    ChargePointId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    ConnectorId = table.Column<int>(type: "int", nullable: false),
                    StartTagId = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    StartTime = table.Column<DateTime>(type: "datetime2", nullable: false),
                    MeterStart = table.Column<double>(type: "float", nullable: false),
                    StartResult = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                    StopTagId = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                    StopTime = table.Column<DateTime>(type: "datetime2", nullable: true),
                    MeterStop = table.Column<double>(type: "float", nullable: true),
                    StopReason = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Transactions", x => x.TransactionId);
                    table.ForeignKey(
                        name: "FK_Transactions_ChargePoint",
                        column: x => x.ChargePointId,
                        principalTable: "ChargePoint",
                        principalColumn: "ChargePointId");
                });

            migrationBuilder.CreateIndex(
                name: "ChargePoint_Identifier",
                table: "ChargePoint",
                column: "ChargePointId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MessageLog_ChargePointId",
                table: "MessageLog",
                column: "LogTime");

            migrationBuilder.CreateIndex(
                name: "IX_Transactions_ChargePointId_ConnectorId",
                table: "Transactions",
                columns: new[] { "ChargePointId", "ConnectorId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ChargeTags");

            migrationBuilder.DropTable(
                name: "ConnectorStatus");

            migrationBuilder.DropTable(
                name: "MessageLog");

            migrationBuilder.DropTable(
                name: "Transactions");

            migrationBuilder.DropTable(
                name: "ChargePoint");
        }
    }
}
