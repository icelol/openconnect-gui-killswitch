Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
Name "OpenConnect VPN + Kill Switch ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\OpenConnect-GUI-KillSwitch"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show
!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Russian"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This build requires Windows x64." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "OpenConnect and system protection" Main
  SectionIn RO
  ; Stop the prior runtime while preserving persistent protection and ON intent.
  IfFileExists "$INSTDIR\openconnect-gui.exe" 0 fresh
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --stop-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Could not stop the previous OpenConnect service. Close its interface and retry." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  fresh:
  SetOutPath "$INSTDIR"
  File /r "${STAGE}\*"
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --install-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The OpenConnect service could not be installed. See the installation details." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  StrCpy $1 0
  ready_retry:
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --service-ready'
  Pop $0
  ${If} $0 != 0
    IntOp $1 $1 + 1
    ${If} $1 < 10
      Sleep 500
      Goto ready_retry
    ${EndIf}
    MessageBox MB_ICONSTOP "The OpenConnect service did not become ready." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\OpenConnect Kill Switch"
  CreateShortCut "$SMPROGRAMS\OpenConnect Kill Switch\OpenConnect.lnk" "$INSTDIR\openconnect-gui.exe"
  CreateShortCut "$SMPROGRAMS\OpenConnect Kill Switch\Remove.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "DisplayName" "OpenConnect VPN + Kill Switch"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "OpenConnectKillSwitch"
SectionEnd

Section "Open the interface at user login" Startup
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "OpenConnectKillSwitch" '$\"$INSTDIR\openconnect-gui.exe$\"'
SectionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --uninstall-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenConnect could not confirm removal of its own filters. Nothing else was deleted." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "OpenConnectKillSwitch"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch"
  RMDir /r "$SMPROGRAMS\OpenConnect Kill Switch"
  RMDir /r "$COMMONAPPDATA\OpenConnect-GUI-KillSwitch"
  RMDir /r "$INSTDIR"
SectionEnd
