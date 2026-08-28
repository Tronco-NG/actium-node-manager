!macro customInstall
  DetailPrint "Configurando e instalando Actium Node Supervisor como Servicio de Windows..."
  IfFileExists "$INSTDIR\resources\supervisor\actium-node-supervisor.exe" 0 +2
    ExecWait '"$INSTDIR\resources\supervisor\actium-node-supervisor.exe" --install --channel stable'
!macroend

!macro customUnInstall
  DetailPrint "Desinstalando Actium Node Supervisor..."
  IfFileExists "C:\ProgramData\Actium\NodeManager\bin\actium-node-supervisor.exe" 0 +2
    ExecWait '"C:\ProgramData\Actium\NodeManager\bin\actium-node-supervisor.exe" --uninstall'
!macroend
