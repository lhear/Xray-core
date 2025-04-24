@echo off

:: Get the latest git commit hash (first 7 characters)
for /f "delims=" %%i in ('git rev-parse HEAD') do set COMMIT_HASH=%%i
set COMMIT_HASH=%COMMIT_HASH:~0,7%

echo Using commit hash: %COMMIT_HASH%

:: Windows build
echo.
echo [1/3] Building Windows version (xray.exe)...
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=0
go build -o output/windows/amd64/xray.exe -trimpath -buildvcs=false -ldflags="-X github.com/xtls/xray-core/core.build=%COMMIT_HASH% -s -w -buildid=" -v ./main
if %errorlevel% neq 0 exit /b %errorlevel%

:: Linux build
echo.
echo [2/3] Building Linux version (xray)...
set GOOS=linux
set GOARCH=amd64
set CGO_ENABLED=0
go build -o output/linux/amd64/xray -trimpath -buildvcs=false -ldflags="-X github.com/xtls/xray-core/core.build=%COMMIT_HASH% -s -w -buildid=" -v ./main
if %errorlevel% neq 0 exit /b %errorlevel%
set GOARCH=arm64
go build -o output/linux/arm64/xray -trimpath -buildvcs=false -ldflags="-X github.com/xtls/xray-core/core.build=%COMMIT_HASH% -s -w -buildid=" -v ./main
if %errorlevel% neq 0 exit /b %errorlevel%

:: Android ARM64 build
echo.
echo [3/3] Building Android version (libxray.so)...
set GOOS=android
set GOARCH=arm64
set CGO_ENABLED=1
set CC="%ANDROID_NDK_HOME%\toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android24-clang.cmd"

go build -o output/android/arm64/libxray.so -trimpath -buildvcs=false -ldflags="-X github.com/xtls/xray-core/core.build=%COMMIT_HASH% -s -w -buildid=" -v ./main
if %errorlevel% neq 0 exit /b %errorlevel%

echo.
echo All builds completed!
pause