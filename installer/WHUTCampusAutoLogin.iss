; WHUTCampusAutoLogin.iss - Inno Setup 6 installer script
;
; 武汉理工校园网助手 Windows 安装器
;
; AppId is a fixed GUID generated once for this product.
; WARNING: Changing AppId will cause Windows to treat this as a different product,
; breaking upgrades and leaving orphan uninstall entries. Do NOT change it.
; The same AppId is used for both development and production installers so that
; a development build installed for testing can be cleanly upgraded by a production
; build later. Development installers MUST NOT be distributed to end users.
;
; Authority sources:
;   AppName / ProductName:   desktop_app/tray/runtime.py  APP_NAME
;   EXE name:                WHUTCampusAutoLogin.spec / generate_windows_version_info.py
;   Publisher:               scripts/generate_windows_version_info.py LegalCopyright
;   Startup shortcut name:   desktop_app/autostart/windows_startup.py SHORTCUT_NAME
;   APPDATA dir:             desktop_app/runtime_logs.py APP_DIR_NAME
;
; Build parameters are injected by scripts/build_windows_installer.ps1 via /D
; preprocessor defines. Do NOT call ISCC.exe directly; always use the build script.
;
; Required defines (passed by build script):
;   AppVersionStr  - e.g. "0.1.0"
;   InputDir       - absolute path to dist\WHUTCampusAutoLogin
;   OutputDir      - absolute path to installer output directory
;   OutputBasename - e.g. "WHUTCampusAutoLogin-0.1.0-development-setup"
;   BuildEnv       - "development" or "production"

#ifndef AppVersionStr
  #error AppVersionStr must be defined. Use scripts\build_windows_installer.ps1.
#endif
#ifndef InputDir
  #error InputDir must be defined. Use scripts\build_windows_installer.ps1.
#endif
#ifndef OutputDir
  #error OutputDir must be defined. Use scripts\build_windows_installer.ps1.
#endif
#ifndef OutputBasename
  #error OutputBasename must be defined. Use scripts\build_windows_installer.ps1.
#endif
#ifndef BuildEnv
  #error BuildEnv must be defined. Use scripts\build_windows_installer.ps1.
#endif

[Setup]
; --- Product identity ---
; Fixed product GUID. DO NOT CHANGE after first release.
; See comment at top of file about AppId stability.
AppId={{8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8}
AppName=武汉理工校园网助手
AppVersion={#AppVersionStr}
AppPublisher=Caesar843
AppPublisherURL=https://github.com/Caesar843
AppSupportURL=https://github.com/Caesar843
AppUpdatesURL=https://github.com/Caesar843

; --- Installation scope: current user, no admin required ---
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=

; --- Architecture ---
; x64 Windows 10/11 only
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; --- Default install directory ---
; Uses {localappdata}\Programs\ so no admin elevation is needed
DefaultDirName={localappdata}\Programs\WHUTCampusAutoLogin
DefaultGroupName=武汉理工校园网助手

; --- Installer appearance ---
DisableProgramGroupPage=yes
DisableWelcomePage=no
DisableReadyPage=no
ShowLanguageDialog=no

; --- Paths ---
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBasename}
SetupIconFile={#InputDir}\_internal\assets\windows\whut_campus_auto_login.ico
UninstallDisplayIcon={app}\WHUTCampusAutoLogin.exe

; --- Compression ---
Compression=lzma2/ultra64
SolidCompression=yes
LZMAUseSeparateProcess=yes

; --- Versioning for upgrade detection ---
VersionInfoVersion={#AppVersionStr}
VersionInfoProductName=武汉理工校园网助手
VersionInfoDescription=武汉理工校园网自动登录工具
VersionInfoCompany=Caesar843
VersionInfoCopyright=Copyright (C) 2026 Caesar843

; --- Uninstall ---
UninstallDisplayName=武汉理工校园网助手
CreateUninstallRegKey=yes

; --- Running application handling ---
; Prompt user to close the running app before installing/upgrading.
; Only targets this specific EXE; does not kill unrelated processes.
CloseApplications=yes
CloseApplicationsFilter=WHUTCampusAutoLogin.exe
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Desktop shortcut: optional, default OFF per spec
Name: "desktopicon"; Description: "在桌面创建快捷方式"; GroupDescription: "附加图标:"; Flags: unchecked
; Post-install launch: optional, default ON
Name: "launchapp"; Description: "安装完成后启动应用"; GroupDescription: "完成操作:"; Flags: checkedonce

[Files]
; Recursively install entire PyInstaller onedir.
; WHUTCampusAutoLogin.exe - main executable
Source: "{#InputDir}\WHUTCampusAutoLogin.exe"; DestDir: "{app}"; Flags: ignoreversion
; _internal\ - all runtime dependencies (Qt plugins, cryptography, assets, etc.)
Source: "{#InputDir}\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Start Menu shortcut (always created)
Name: "{group}\武汉理工校园网助手"; Filename: "{app}\WHUTCampusAutoLogin.exe"; IconFilename: "{app}\WHUTCampusAutoLogin.exe"
; Desktop shortcut (optional task, unchecked by default)
Name: "{autodesktop}\武汉理工校园网助手"; Filename: "{app}\WHUTCampusAutoLogin.exe"; IconFilename: "{app}\WHUTCampusAutoLogin.exe"; Tasks: desktopicon

[Run]
; Launch application after install. NOT elevated. No hidden arguments.
; Uses --startup-tray so the app starts quietly in the system tray.
Filename: "{app}\WHUTCampusAutoLogin.exe"; Parameters: "--startup-tray"; Description: "启动武汉理工校园网助手"; Flags: nowait postinstall skipifsilent; Tasks: launchapp

[UninstallDelete]
; Remove the application Startup folder shortcut if it exists.
; This is the EXACT shortcut filename from:
;   desktop_app/autostart/windows_startup.py  SHORTCUT_NAME = "whut-campus-auto-login.lnk"
; ONLY this precise file is targeted. No wildcards. No APPDATA deletion.
; User data (%APPDATA%\WHUTCampusAutoLogin\: logs, config, license, credentials)
; is intentionally PRESERVED so reinstall / upgrade does not destroy user state.
Type: files; Name: "{userappdata}\Microsoft\Windows\Start Menu\Programs\Startup\whut-campus-auto-login.lnk"

[Code]
// --- Downgrade Protection ---
// Inno Setup 6 does not have an "AllowDowngrade" [Setup] directive.
// We implement product-level downgrade protection in InitializeSetup:
// 1. Read the installed version from HKCU (and fallback to HKLM) uninstall key
//    for this specific AppId: {8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8}_is1.
// 2. Parse and compare numeric version parts (M.m.p).
// 3. If installed version > setup version: show an error message and abort (Result := False).
// 4. Same version (repair install), higher setup version (upgrade), or fresh install: continue (Result := True).

function ParseNextVersionPart(var S: String): Integer;
var
  DotPos: Integer;
  PartStr: String;
begin
  DotPos := Pos('.', S);
  if DotPos > 0 then
  begin
    PartStr := Copy(S, 1, DotPos - 1);
    S := Copy(S, DotPos + 1, Length(S) - DotPos);
  end
  else
  begin
    PartStr := S;
    S := '';
  end;
  Result := StrToIntDef(PartStr, 0);
end;

function CompareVersionStrings(V1, V2: String): Integer;
var
  N1, N2: Integer;
begin
  Result := 0;
  while (Length(V1) > 0) or (Length(V2) > 0) do
  begin
    N1 := ParseNextVersionPart(V1);
    N2 := ParseNextVersionPart(V2);
    if N1 > N2 then
    begin
      Result := 1;
      Exit;
    end;
    if N1 < N2 then
    begin
      Result := -1;
      Exit;
    end;
  end;
end;

function InitializeSetup(): Boolean;
var
  InstalledVersionStr: String;
  CurrentVersionStr: String;
  Unkey: String;
begin
  Result := True;
  Unkey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{8A3F2B1C-4D7E-4F9A-B2C3-D1E4F5A6B7C8}_is1';
  InstalledVersionStr := '';

  if not RegQueryStringValue(HKCU, Unkey, 'DisplayVersion', InstalledVersionStr) then
  begin
    RegQueryStringValue(HKLM, Unkey, 'DisplayVersion', InstalledVersionStr);
  end;

  if InstalledVersionStr <> '' then
  begin
    CurrentVersionStr := '{#AppVersionStr}';
    if CompareVersionStrings(InstalledVersionStr, CurrentVersionStr) > 0 then
    begin
      MsgBox('检测到系统中已安装更新版本的武汉理工校园网助手 (' + InstalledVersionStr + ')。' + #13#10 + #13#10 +
             '无法使用较低版本的安装包 (' + CurrentVersionStr + ') 覆盖安装。' + #13#10 +
             '安装程序将退出。', mbCriticalError, MB_OK);
      Result := False;
    end;
  end;
end;
