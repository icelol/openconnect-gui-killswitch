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
  StrCpy $INSTDIR "$PROGRAMFILES64\OpenConnect-GUI-KillSwitch"
FunctionEnd

Section "OpenConnect and system protection" Main
  SectionIn RO
  ; Stop the prior runtime while preserving persistent protection and ON intent.
  IfFileExists "$INSTDIR\openconnect-gui.exe" 0 fresh
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --check-interface-closed'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Close the OpenConnect interface and retry. The service and protection were not changed." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
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
  ; Ownership must stay with the administrator group, including on runners or
  ; endpoints whose elevated token uses the individual account as default owner.
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /setowner "*S-1-5-32-544" /T /C'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Cannot protect ownership of the installed runtime." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  ; Remove inherited per-machine writer grants from Program Files. Only SYSTEM
  ; and Administrators may change the runtime; desktop users retain read/execute.
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /reset'
  Pop $0
  ${If} $0 == 0
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"'
    Pop $0
  ${EndIf}
  ${If} $0 == 0
    nsExec::ExecToLog '"$SYSDIR\icacls.exe" "$INSTDIR\*" /reset /T /C'
    Pop $0
  ${EndIf}
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Cannot protect access to the installed runtime." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  nsExec::ExecToStack '"$INSTDIR\openconnect-gui.exe" --install-service'
  Pop $0
  Pop $2
  DetailPrint $2
  FileOpen $3 "$INSTDIR\installer.log" a
  FileWrite $3 "Service installation: exit=$0$\r$\n$2$\r$\n"
  FileClose $3
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
  StrCpy $INSTDIR "$PROGRAMFILES64\OpenConnect-GUI-KillSwitch"
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --check-interface-closed'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "Close the OpenConnect interface and retry. The service and protection were not changed." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  nsExec::ExecToLog '"$INSTDIR\openconnect-gui.exe" --uninstall-service'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "OpenConnect could not confirm removal of its own filters. Nothing else was deleted." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  ; Report cleanup failures instead of silently declaring successful removal.
  ClearErrors
  RMDir /r "$APPDATA\OpenConnect-GUI-KillSwitch"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP "The service and its network rules were removed, but OpenConnect data files are still in use. Close OpenConnect and retry removal." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  ClearErrors
  RMDir /r "$INSTDIR"
  ${If} ${Errors}
    MessageBox MB_ICONSTOP "The service and its network rules were removed, but some OpenConnect program files could not be deleted. Restart Windows, reinstall OpenConnect, then retry removal." /SD IDOK
    SetErrorLevel 1
    Abort
  ${EndIf}
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "OpenConnectKillSwitch"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenConnectKillSwitch"
  RMDir /r "$SMPROGRAMS\OpenConnect Kill Switch"
SectionEnd
