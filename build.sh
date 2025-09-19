#!/usr/bin/env bash
# Build helper for MSSQL Security Assessment Tool
# Self-contained build script for cross-platform compilation
# Usage:
#   ./build.sh [runtime]
# Examples:
#   ./build.sh            # Windows 64-bit .exe output (default)
#   ./build.sh win-x64    # Windows 64-bit .exe output
#   ./build.sh win-x86    # Windows 32-bit .exe output
#   ./build.sh linux-x64  # Linux 64-bit binary

set -e
RID="${1:-win-x64}"
PROJ="MSSQL.csproj"
OUT="bin/publish-$RID"

if ! command -v dotnet >/dev/null 2>&1; then
  echo "[!] dotnet SDK not found. Install dotnet-sdk then retry." >&2
  exit 1
fi

echo "[*] MSSQL Security Assessment Tool - Cross-Platform Build"
echo "[*] Publishing self-contained single-file for $RID -> $OUT"

# Restore dependencies
dotnet restore "$PROJ"

# Build and publish
dotnet publish "$PROJ" -c Release -o "$OUT" -r "$RID" \
  --self-contained true \
  /p:PublishSingleFile=true \
  /p:IncludeNativeLibrariesForSelfExtract=true \
  /p:EnableCompressionInSingleFile=true

echo "[+] Build completed successfully!"
echo "[+] Output files: $OUT/"

# Show the generated executable
if [ "$RID" = "win-x64" ] || [ "$RID" = "win-x86" ]; then
    echo "[+] Windows executable: $OUT/MSSQL.exe"
else
    echo "[+] Binary: $OUT/MSSQL"
fi

echo ""
echo "Usage examples:"
echo "  Windows: $OUT/MSSQL.exe --server <target> --database <db>"
echo "  Linux:   $OUT/MSSQL --server <target> --database <db>"
echo ""
echo "For help: $OUT/MSSQL(.exe) --help" 