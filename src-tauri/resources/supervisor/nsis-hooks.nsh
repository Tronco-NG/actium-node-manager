!macro customInstall
  StrCpy $0 "$INSTDIR\supervisor\actium-node-supervisor.exe"
  IfFileExists "$0" doSupervisorInstall 0
  StrCpy $0 "$INSTDIR\resources\supervisor\actium-node-supervisor.exe"
  IfFileExists "$0" doSupervisorInstall 0
  Abort "El paquete no contiene Actium Node Supervisor."
doSupervisorInstall:
  DetailPrint "Actualizando Actium Node Supervisor (stable + lab)..."
  ClearErrors
  ExecWait '"$0" --install --channel both' $1
  IntCmp $1 0 supervisorInstallOk 0 0
  Abort "No se pudo instalar o actualizar Actium Node Supervisor (codigo $1)."
supervisorInstallOk:
!macroend

!macro customUnInstall
  StrCpy $0 "$INSTDIR\supervisor\actium-node-supervisor.exe"
  IfFileExists "$0" doSupervisorUninstall 0
  StrCpy $0 "$INSTDIR\resources\supervisor\actium-node-supervisor.exe"
  IfFileExists "$0" doSupervisorUninstall skipSupervisorUninstall
doSupervisorUninstall:
  DetailPrint "Desinstalando Actium Node Supervisor (stable + lab)..."
  ExecWait '"$0" --uninstall --channel both'
skipSupervisorUninstall:
!macroend
