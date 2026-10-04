Option Explicit
' AOTE lightweight process watchdog (kept ASCII-only on purpose: wscript
' parses non-BOM script files as ANSI, so non-ASCII text would be garbled).
' Run by Windows Task Scheduler every N minutes. No console window is ever
' created: wscript.exe is a GUI-subsystem host (PE Subsystem=2), and the
' application it launches is GUI-subsystem too.
' The script only READS state and never writes files: all audit lines are
' written by the main application, keeping one single text encoding.

Dim fso, shell, scriptPath, appDir, exePath, stateFile
Dim running, raw, lowered, ts, wmi, procs, p

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

' <App>\scripts\aote_watchdog.vbs  ->  <App>
scriptPath = WScript.ScriptFullName
appDir = fso.GetParentFolderName(fso.GetParentFolderName(scriptPath))
exePath = fso.BuildPath(appDir, "AOTE.exe")
stateFile = fso.BuildPath(appDir, "guardian_state.json")

' Target missing (moved/uninstalled but the task survived): exit quietly
If Not fso.FileExists(exePath) Then WScript.Quit 0

' ---- 1) already running? match by full executable path ----
' A full-path match avoids mistaking another copy for this one, and it sees the
' onefile bootloader process the very moment it appears, so the startup window
' can never cause a duplicate launch.
running = False
On Error Resume Next
Set wmi = GetObject("winmgmts:\\.\root\cimv2")
Set procs = wmi.ExecQuery("SELECT ExecutablePath FROM Win32_Process WHERE Name='AOTE.exe'")
If Err.Number = 0 Then
  For Each p In procs
    If Not IsNull(p.ExecutablePath) Then
      If LCase(p.ExecutablePath) = LCase(exePath) Then
        running = True
        Exit For
      End If
    End If
  Next
Else
  ' WMI unavailable: fall back to process-name match (prefer skipping a
  ' restart over launching a duplicate)
  Err.Clear
  Set procs = wmi.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name='AOTE.exe'")
  If Err.Number = 0 Then
    If procs.Count > 0 Then running = True
  End If
End If
Err.Clear
On Error GoTo 0

If running Then WScript.Quit 0

' ---- 2) policy from guardian_state.json (substring test; spaces stripped) ----
If fso.FileExists(stateFile) Then
  On Error Resume Next
  Set ts = fso.OpenTextFile(stateFile, 1)
  raw = ts.ReadAll
  ts.Close
  Err.Clear
  On Error GoTo 0
  lowered = LCase(Replace(raw, " ", ""))
  ' Authorized exit (admin password / hotkey): never auto restart
  If InStr(lowered, """authorized_exit"":true") > 0 Then WScript.Quit 0
  ' Restart disabled by configuration
  If InStr(lowered, """restart_on_unexpected_exit"":false") > 0 Then WScript.Quit 0
End If

' ---- 3) start the application hidden and do not wait ----
shell.Run """" & exePath & """", 0, False
WScript.Quit 0
