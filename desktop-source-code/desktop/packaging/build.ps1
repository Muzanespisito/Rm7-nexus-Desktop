param(
    [string]$Python = "py",
    [string]$NodeExe = "",
    [ValidateSet("nuitka", "pyinstaller")]
    [string]$Backend = "nuitka",
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$vendorDir = Join-Path $root "vendor\node"
$vendorNode = Join-Path $vendorDir "node.exe"
$stage = Join-Path $root "build\windows-stage"
$nuitkaOut = Join-Path $root "build\nuitka"
$bundle = Join-Path $root "dist\RM7NexusDesktop"
$releaseDir = Join-Path $root "RM7-Nexus-Releases\Windows-x64"
$installer = Join-Path $releaseDir "RM7-Nexus-Setup-x64.exe"
$helper = Join-Path $PSScriptRoot "windows_release.py"

function Invoke-Checked {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Command failed with exit code $LASTEXITCODE."
    }
}

Push-Location $root
try {
    $pythonCommand = Get-Command $Python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python was not found. Pass -Python C:\path\to\python.exe."
    }

    $pyBits = (& $Python -c "import struct; print(struct.calcsize('P') * 8)").Trim()
    if ($pyBits -ne "64") {
        throw "The build Python runtime must be 64-bit (found $pyBits-bit)."
    }

    $version = (& $Python -c "from desktop.config import APP_VERSION; print(APP_VERSION)").Trim()
    if (-not $version) {
        throw "Could not determine the desktop application version."
    }

    if (-not (Test-Path $vendorNode)) {
        New-Item -ItemType Directory -Force -Path $vendorDir | Out-Null
        if ($NodeExe) {
            Copy-Item -LiteralPath $NodeExe -Destination $vendorNode
        } else {
            $node = Get-Command node -ErrorAction SilentlyContinue
            if (-not $node) {
                throw "Node.js was not found. Install Node.js x64 or pass -NodeExe C:\path\to\node.exe."
            }
            Copy-Item -LiteralPath $node.Source -Destination $vendorNode
        }
    } elseif ($NodeExe) {
        Copy-Item -LiteralPath $NodeExe -Destination $vendorNode -Force
    }

    $arch = (& $vendorNode -p "process.arch").Trim()
    if ($arch -ne "x64") {
        throw "The bundled Node.js runtime must be x64 (found $arch)."
    }

    Invoke-Checked $Python @("-m", "pip", "install", "--disable-pip-version-check", "-r", (Join-Path $PSScriptRoot "requirements-desktop.txt"))
    if ($Backend -eq "nuitka") {
        Invoke-Checked $Python @("-m", "pip", "install", "--disable-pip-version-check", "nuitka==4.3.1", "ordered-set", "zstandard")
    }

    if (-not (Test-Path (Join-Path $root "node_modules\wasmoon\package.json"))) {
        Invoke-Checked "npm.cmd" @("ci", "--omit=dev")
    }

    if (Test-Path $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    Invoke-Checked $Python @(
        $helper, "stage",
        "--root", $root,
        "--stage", $stage,
        "--node-exe", $vendorNode
    )

    if (Test-Path $bundle) {
        Remove-Item -LiteralPath $bundle -Recurse -Force
    }
    if (Test-Path $nuitkaOut) {
        Remove-Item -LiteralPath $nuitkaOut -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path (Join-Path $root "dist") | Out-Null

    if ($Backend -eq "nuitka") {
        $icon = Join-Path $PSScriptRoot "assets\rm7nexus.ico"
        $entry = Join-Path $PSScriptRoot "entry_windows.py"
        Invoke-Checked $Python @(
            "-m", "nuitka",
            "--mode=standalone",
            "--assume-yes-for-downloads",
            "--output-dir=$nuitkaOut",
            "--output-folder-name=RM7NexusDesktop.dist",
            "--output-filename=RM7NexusDesktop.exe",
            "--remove-output",
            "--no-pyi-file",
            "--windows-console-mode=disable",
            "--windows-icon-from-ico=$icon",
            "--company-name=RM7 Nexus",
            "--product-name=RM7 Nexus",
            "--file-description=RM7 Nexus Desktop",
            "--file-version=$version",
            "--product-version=$version",
            "--include-package=desktop",
            "--include-package=cryptography",
            "--nofollow-import-to=tkinter",
            "--nofollow-import-to=gi",
            "--nofollow-import-to=secretstorage",
            "--nofollow-import-to=jeepney",
            "--nofollow-import-to=PyQt5",
            "--nofollow-import-to=PyQt6",
            "--nofollow-import-to=PySide2",
            "--nofollow-import-to=PySide6",
            "--include-data-dir=$stage=.",
            $entry
        )
        $nuitkaDist = Join-Path $nuitkaOut "RM7NexusDesktop.dist"
        if (-not (Test-Path (Join-Path $nuitkaDist "RM7NexusDesktop.exe"))) {
            throw "Nuitka did not produce RM7NexusDesktop.exe in $nuitkaDist."
        }
        Move-Item -LiteralPath $nuitkaDist -Destination $bundle
    } else {
        $env:RM7_WINDOWS_STAGE = $stage
        try {
            Invoke-Checked $Python @(
                "-m", "PyInstaller",
                "--clean",
                "--noconfirm",
                "--distpath", (Join-Path $root "dist"),
                "--workpath", (Join-Path $root "build\pyinstaller"),
                (Join-Path $PSScriptRoot "rm7-desktop-windows.spec")
            )
        } finally {
            Remove-Item Env:\RM7_WINDOWS_STAGE -ErrorAction SilentlyContinue
        }
    }

    foreach ($pattern in @("*.pyi", "*.pdb")) {
        Get-ChildItem -LiteralPath $bundle -Recurse -File -Filter $pattern -ErrorAction SilentlyContinue |
            Remove-Item -Force
    }
    Get-ChildItem -LiteralPath $bundle -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
        Remove-Item -Recurse -Force
    Invoke-Checked $Python @($helper, "verify-bundle", "--bundle", $bundle)
    Write-Host "Built $bundle"

    if (-not $SkipInstaller) {
        $iscc = Get-ChildItem -Path @(
            "${env:ProgramFiles(x86)}\Inno Setup*\ISCC.exe",
            "$env:ProgramFiles\Inno Setup*\ISCC.exe",
            "$env:LOCALAPPDATA\Programs\Inno Setup*\ISCC.exe"
        ) -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1 -ExpandProperty FullName
        if (-not $iscc) {
            throw "Inno Setup was not found. Install it or pass -SkipInstaller to build only the portable folder."
        }
        New-Item -ItemType Directory -Force -Path $releaseDir | Out-Null
        foreach ($old in @($installer, (Join-Path $releaseDir "SHA256SUMS.txt"), (Join-Path $releaseDir "RELEASE-INFO.txt"))) {
            if (Test-Path $old) {
                Remove-Item -LiteralPath $old -Force
            }
        }
        Invoke-Checked $iscc @("/DMyAppVersion=$version", (Join-Path $PSScriptRoot "rm7nexus.iss"))
        if (-not (Test-Path $installer)) {
            throw "Expected installer was not created: $installer"
        }
        Invoke-Checked $Python @($helper, "verify-installer", "--installer", $installer, "--version", $version)
        Invoke-Checked $Python @($helper, "write-checksums", "--directory", $releaseDir, "--installer", $installer)
        Invoke-Checked $Python @(
            $helper, "write-release-info",
            "--installer", $installer,
            "--bundle", $bundle,
            "--version", $version,
            "--backend", $(if ($Backend -eq "nuitka") { "Nuitka 4.3.1 standalone" } else { "PyInstaller 6 one-folder fallback" })
        )
        Write-Host "Built $installer"
    }
} finally {
    Pop-Location
}
