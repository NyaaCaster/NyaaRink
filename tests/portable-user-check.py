"""Opt-in isolated loopback SSH check in the interactive least-privilege token.

Does not create an account or modify sshd services. Cleans the one-off task and
temporary files. Requires a prebuilt portable-openssh-check.cjs and official ZIP.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid
from xml.sax.saxutils import escape


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--openssh', type=Path, required=True)
    args = parser.parse_args()
    name = 'NyaaRink-portable-check-' + uuid.uuid4().hex
    base = Path(os.environ['USERPROFILE']) / 'AppData' / 'Local' / 'Temp'
    with tempfile.TemporaryDirectory(prefix=name, dir=base) as tmp:
        root = Path(tmp)
        result = root / 'result.json'
        script = root / 'check.py'
        script.write_text('import ctypes,json,os,subprocess\nfrom pathlib import Path\n'
                          'data={"elevated":bool(ctypes.windll.shell32.IsUserAnAdmin())}\n'
                          'try:\n'
                          ' if data["elevated"]: raise RuntimeError("Unexpected elevated token")\n'
                          f' env=dict(os.environ,NYAARINK_PORTABLE_SSH={str(args.openssh.resolve())!r})\n'
                          f' r=subprocess.run(["node.exe",{str(args.probe.resolve())!r}],env=env,capture_output=True,text=True,timeout=75,creationflags=0x08000000)\n'
                          ' data.update(code=r.returncode,stdout=r.stdout,stderr=r.stderr)\n'
                          'except Exception as e: data.update(code=1,error=str(e))\n'
                          f'Path({str(result)!r}).write_text(json.dumps(data),encoding="utf-8")\n', encoding='utf-8')
        user = subprocess.check_output(['whoami.exe'], text=True).strip()
        pythonw = Path(sys.executable).with_name('pythonw.exe')
        if not pythonw.exists():
            raise RuntimeError('pythonw unavailable; refusing visible helper')
        xml = root / 'task.xml'
        xml.write_text(f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Principals><Principal id="User"><UserId>{escape(user)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><Hidden>true</Hidden><ExecutionTimeLimit>PT2M</ExecutionTimeLimit><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries></Settings>
<Actions Context="User"><Exec><Command>{escape(str(pythonw))}</Command><Arguments>&quot;{escape(str(script))}&quot;</Arguments></Exec></Actions></Task>''', encoding='utf-16')
        try:
            subprocess.run(['schtasks.exe', '/Create', '/TN', name, '/XML', str(xml)], check=True, capture_output=True)
            subprocess.run(['schtasks.exe', '/Run', '/TN', name], check=True, capture_output=True)
            deadline = time.monotonic() + 100
            while not result.exists() and time.monotonic() < deadline:
                time.sleep(1)
            data = json.loads(result.read_text(encoding='utf-8'))
            print(json.dumps(data, ensure_ascii=False))
            if data.get('code') != 0:
                raise SystemExit(1)
        finally:
            subprocess.run(['schtasks.exe', '/End', '/TN', name], capture_output=True)
            subprocess.run(['schtasks.exe', '/Delete', '/TN', name, '/F'], capture_output=True)


if __name__ == '__main__':
    main()
