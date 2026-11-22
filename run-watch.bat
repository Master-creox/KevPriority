@echo off
REM KevPriority watch mode - double-click this file to start the monitor.
REM It scans CISA KEV + EPSS every 6 hours and reports only what changed
REM since the last run. Reports land in the reports\ folder.
REM Close this window to stop watching.
cd /d "%~dp0"
python kevpriority.py --watch
pause
