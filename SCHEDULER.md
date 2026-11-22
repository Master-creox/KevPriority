# Run KevPriority Watch automatically (Windows Task Scheduler)

Watch mode (`python kevpriority.py --watch`) is a loop: it scans every 6
hours and reports only what changed. You can start it by double-clicking
`run-watch.bat`. These steps make Windows start it for you, so you never
have to remember — for example every time you log on.

No admin service, no background service install — just the built-in
Windows Task Scheduler. The task runs the same `.bat` file you can
double-click yourself.

## Create the task (one time, about 2 minutes)

1. Press `Win + R`, type `taskschd.msc`, press Enter. Task Scheduler opens.
2. In the right-hand pane, click **Create Task...** (use "Create Task",
   not "Create Basic Task" — we need the extra settings below).
3. **General tab**
   - Name: `KevPriority Watch`
   - Select **"Run only when user is logged on"** — this keeps the
     console window visible so you can see each scan happen.
   - Leave "Run with highest privileges" unchecked.
4. **Triggers tab** → **New...**
   - "Begin the task:" → **At log on**. Click OK.
   - (Or pick **Daily** and a time, e.g. 9:00 AM, if you would rather
     have it start once a day instead of at every logon.)
5. **Actions tab** → **New...**
   - Action: **Start a program**.
   - "Program/script": click **Browse...** and pick `run-watch.bat`
     inside your KevPriority folder, e.g.
     `D:\expermental zone\KevPriority-main\KevPriority-main\run-watch.bat`
   - Leave "Add arguments" and "Start in" empty — the `.bat` file
     switches to its own folder by itself.
   - Click OK.
6. **Settings tab**
   - **Uncheck** "Stop the task if it runs longer than" — watch mode is
     meant to run for hours; the default 3-day limit would kill it.
   - "If the task is already running, then the following rule applies:"
     → **Do not start a new instance**.
   - Click OK. If Windows asks for your password, enter your Windows
     password (this lets the task start at logon).

## Test it

- In Task Scheduler, right-click `KevPriority Watch` → **Run**. A black
  console window opens and the first scan runs. The first run only saves
  the baseline ("baseline saved, N CVEs tracked") — it does not report
  everything as new.
- To see what changed later, open the `reports\` folder in your
  KevPriority folder: `changes-*.txt` files hold each cycle's changes
  and `watch.log` holds one line per cycle.

## Stop it

- Close the black console window, **or** in Task Scheduler right-click
  `KevPriority Watch` → **End**.
- To remove the automation completely, right-click the task → **Delete**.
  This only removes the schedule; your files and `state.json` stay put.

## Notes

- The laptop must be on (and logged in, if you chose "At log on") for a
  cycle to run. A missed cycle is simply skipped — the next cycle still
  compares against the last *successful* run, so nothing is lost.
- If a cycle fails (no internet, feed down), the state file is left
  untouched, the failure is written to `watch.log`, and the next cycle
  retries. A failed scan can never make real changes look like "nothing
  changed".
- `state.json` is local only and gitignored — it is never uploaded to
  GitHub. Deleting it just re-baselines the next run (the next cycle
  saves a fresh baseline instead of reporting changes).
