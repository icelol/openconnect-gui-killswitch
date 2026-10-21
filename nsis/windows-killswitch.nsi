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
    MessageBox MB_ICONSTOP "This build requires Windows x64."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section "OpenConnect and system protection" Main
  SectionIn RO
  ; Stop the prior runtime before replacing its DLLs. Never globally reset WFP.
  IfFileExists "$INSTDIR\openconnect-gui.exe" 0 fresh
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --uninstall-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Could not stop and recover the previous OpenConnect service. Installation stopped."
    Abort
  ${EndIf}
  fresh:
  SetOutPath "$INSTDIR"
  File /r "${STAGE}\*"
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --install-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The OpenConnect service could not be installed. See the installation details."
    Abort
  ${EndIf}
  Sleep 2000
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --service-ready'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The OpenConnect service did not become ready."
    Abort
  ${EndIf}
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\OpenConnect Kill Switch"
  CreateShortCut "$SMPROGRAMS\OpenConnect Kill Switch\OpenConnect.lnk" "$INSTDIR\openconnect-gui.exe"
  CreateShortCut "$SMPROGRAMS\OpenConnect Kill Switch\Remove.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "DisplayName" "OpenConnect VPN + Kill Switch"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
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
    MessageBox MB_ICONSTOP "OpenConnect could not confirm removal of its own filters. Nothing else was deleted."
    Abort
  ${EndIf}
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "OpenConnectKillSwitch"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch"
  RMDir /r "$SMPROGRAMS\OpenConnect Kill Switch"
  RMDir /r "$COMMONAPPDATA\OpenConnect-GUI-KillSwitch"
  RMDir /r "$INSTDIR"
SectionEnd
