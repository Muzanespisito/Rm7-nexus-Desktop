#ifndef MyAppVersion
  #define MyAppVersion "0.1.1"
#endif

#define MyAppName "RM7 Nexus"
#define MyAppExeName "RM7NexusDesktop.exe"
#define MyAppPublisher "RM7 Nexus"

[Setup]
AppId={{941707d9-cb95-414d-81d3-860b4f0d57b0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\RM7 Nexus
DefaultGroupName=RM7 Nexus
DisableProgramGroupPage=yes
OutputDir=..\..\RM7-Nexus-Releases\Windows-x64
OutputBaseFilename=RM7-Nexus-Setup-x64
SetupIconFile=assets\rm7nexus.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=RM7 Nexus Desktop Installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}.0
VersionInfoVersion={#MyAppVersion}.0
SetupLogging=yes
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
CloseApplications=yes
RestartApplications=no
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "..\..\dist\RM7NexusDesktop\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\RM7 Nexus"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\RM7 Nexus"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,RM7 Nexus}"; Flags: nowait postinstall skipifsilent
