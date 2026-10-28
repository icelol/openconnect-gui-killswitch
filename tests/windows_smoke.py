#!/usr/bin/env python3
"""Destructive networking QA ONLY on a disposable Windows GitHub Actions runner.

Never run this on an employee endpoint. An independent recovery watchdog is
started before ON. It uses the installed runtime's owned-provider recovery.
"""
import ctypes
from ctypes import wintypes
import json
import http.client
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import time

assert os.name == 'nt' and os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Windows', 'Disposable Windows runner required'
assert ctypes.windll.shell32.IsUserAnAdmin(), 'Administrator runner required'
root = pathlib.Path(__file__).resolve().parents[1]
runtime = pathlib.Path(os.environ['ProgramFiles'])/'OpenConnect-GUI-KillSwitch/openconnect-gui.exe'
data = pathlib.Path(os.environ['ProgramData'])/'OpenConnect-GUI-KillSwitch'

def run(*args, timeout=35):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, errors='replace', timeout=timeout)
    if result.returncode:
        raise AssertionError('Command failed ('+str(result.returncode)+'): '+pathlib.Path(str(args[0])).name+' '+str(args[1:])+'\n'+result.stdout[-3000:]+'\n'+result.stderr[-3000:])
    return result.stdout

if '--watchdog' in sys.argv:
    marker = pathlib.Path(sys.argv[-1])
    for _ in range(180):
        if marker.exists(): sys.exit(0)
        time.sleep(1)
    subprocess.run([str(runtime), '--recover-killswitch'], timeout=45)
    sys.exit(0)

kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.CreateFileW.argtypes = [wintypes.LPCWSTR,wintypes.DWORD,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,wintypes.HANDLE]
kernel.CreateFileW.restype = wintypes.HANDLE
kernel.PeekNamedPipe.argtypes = [wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
kernel.ReadFile.argtypes = [wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
kernel.WriteFile.argtypes = kernel.ReadFile.argtypes
kernel.CloseHandle.argtypes = [wintypes.HANDLE]

class Pipe:
    def __init__(self):
        self.handle = kernel.CreateFileW(r'\\.\pipe\OpenConnectKillSwitch-control-v1',0xc0000000,0,None,3,0x00120000,None)
        assert self.handle != ctypes.c_void_p(-1).value, 'Cannot open authenticated control pipe: '+str(ctypes.get_last_error())
        self.buffer=b'';self.serial=0;self.events=[]
    def close(self):
        if self.handle: kernel.CloseHandle(self.handle);self.handle=None
    def read(self, deadline):
        while time.monotonic()<deadline:
            if b'\n' in self.buffer:
                line,self.buffer=self.buffer.split(b'\n',1);return json.loads(line)
            available=wintypes.DWORD()
            if not kernel.PeekNamedPipe(self.handle,None,0,None,ctypes.byref(available),None):
                raise AssertionError('Control pipe closed: '+str(ctypes.get_last_error()))
            if available.value:
                value=ctypes.create_string_buffer(min(available.value,65536));read=wintypes.DWORD()
                assert kernel.ReadFile(self.handle,value,len(value),ctypes.byref(read),None)
                self.buffer+=value.raw[:read.value];assert len(self.buffer)<=65536
            else: time.sleep(.02)
        raise AssertionError('Service response deadline exceeded')
    def request(self, method, params=None, error=False):
        self.serial+=1
        value=(json.dumps({'id':self.serial,'method':method,'params':params or {}})+'\n').encode()
        sent=wintypes.DWORD();assert kernel.WriteFile(self.handle,value,len(value),ctypes.byref(sent),None) and sent.value==len(value)
        deadline=time.monotonic()+8
        while True:
            reply=self.read(deadline)
            if reply.get('id')==self.serial:
                if error: assert reply.get('error'), 'Invalid request was accepted'
                else: assert not reply.get('error'), reply.get('error')
                return reply.get('result',{})
            self.events.append(reply)
    def settled(self, enabled):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            state=self.request('status');fw=state['firewall']
            if not fw['busy'] and fw['verified'] and fw['armed']==enabled and fw['requested']==enabled:
                return state
            if not fw['busy'] and fw['error']: raise AssertionError(fw['error'])
            time.sleep(.1)
        raise AssertionError('Firewall did not reach confirmed state: '+json.dumps(state))

def external(ip='1.1.1.1', port=443):
    try:
        with socket.create_connection((ip,port),timeout=2):return True
    except OSError:return False

def udp_dns():
    # Public, fixed probe with no local hostnames or search suffixes.
    question=b'\x45\x71\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03one\x03one\x03one\x03one\x00\x00\x01\x00\x01'
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.settimeout(2);probe.sendto(question,('1.1.1.1',53))
            reply,peer=probe.recvfrom(2048)
            return peer==('1.1.1.1',53) and reply[:2]==question[:2] and len(reply)>=12
    except OSError:return False

installer=next((root/'dist').glob('*Setup-windows-x64-*.exe'))
report={'platform':sys.getwindowsversion().build,'version':(root/'VERSION').read_text().strip(),
        'commit':os.environ['GITHUB_SHA'],
        'ci_run':'https://github.com/'+os.environ['GITHUB_REPOSITORY']+'/actions/runs/'+os.environ['GITHUB_RUN_ID']}
marker=root/'dist/windows-watchdog-finished'
marker.unlink(missing_ok=True)
watchdog=None;pipe=None;existing=None;fixture=None;gui=None
foreign='OpenConnect-CI-Unrelated-Policy-78196d3a'
try:
    run(installer,'/S',timeout=90)
    run(runtime,'--service-ready') # Production client verifies SCM identity, not just a pipe name.
    pipe=Pipe();state=pipe.settled(False)
    assert state['service']['version']==report['version']
    report['installation_and_authenticated_status']='passed'
    pipe.request('firewall',{'enabled':'yes'},error=True)
    pipe.request('connect',{'gateway':'https://vpn.example.net','script':'untrusted.cmd'},error=True)
    report['invalid_ipc_requests']='rejected'
    # Run the installed GUI with only its packaged runtime, not MSYS2's PATH.
    clean={**os.environ,'PATH':str(pathlib.Path(os.environ['SystemRoot'])/'System32')}
    gui=subprocess.Popen([str(runtime)],env=clean)
    time.sleep(3);assert gui.poll() is None,'Installed GUI exited at startup'
    gui.terminate();gui.wait(10);gui=None
    report['packaged_gui_startup']='passed'
    run('powershell.exe','-NoProfile','-NonInteractive','-Command',
        "New-NetFirewallRule -Name '"+foreign+"' -DisplayName 'Unrelated CI rule' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress 192.0.2.123 | Out-Null")
    assert external(), 'External baseline is unavailable'
    ipv6=external('2606:4700:4700::1111')
    udp=udp_dns()
    existing=http.client.HTTPSConnection('1.1.1.1',timeout=3,context=ssl.create_default_context())
    existing.request('GET','/cdn-cgi/trace',headers={'Connection':'keep-alive'})
    reply=existing.getresponse();assert reply.status==200;reply.read()
    assert existing.sock is not None,'Persistent TCP baseline is unavailable'
    watchdog=subprocess.Popen([sys.executable,__file__,'--watchdog',str(marker)])
    pipe.request('firewall',{'enabled':True,'gateway':'https://1.1.1.1'})
    pipe.settled(True)
    assert not external(), 'IPv4 traffic escaped enabled protection'
    if ipv6: assert not external('2606:4700:4700::1111'),'IPv6 traffic escaped enabled protection'
    if udp: assert not udp_dns(),'UDP escaped enabled protection'
    try:
        existing.request('GET','/cdn-cgi/trace',headers={'Connection':'keep-alive'})
        reply=existing.getresponse();reply.read();escaped=True
    except (OSError,http.client.HTTPException):escaped=False
    assert not escaped,'An existing TCP flow escaped reauthorization'
    existing.close();existing=None
    diag=pipe.request('diagnostics')
    assert diag['persistentBlockLayers']==4 and diag['ownedFilterCount']>=21,diag
    report['wfp_ipv4']='blocked'
    report['wfp_ipv6']='blocked' if ipv6 else 'baseline unavailable on hosted runner'
    report['wfp_udp']='blocked' if udp else 'baseline unavailable on hosted runner'
    report['existing_tcp_flow']='blocked after policy change'
    report['wfp_filter_policy']=diag
    pipe.request('firewall',{'enabled':True,'gateway':'https://one.one.one.one'})
    pipe.settled(True);assert not external()
    report['new_gateway_dns_while_blocked']='passed'
    # Connect must still be accepted; an unreachable test gateway can be canceled.
    pipe.request('connect',{'gateway':'https://192.0.2.1','protocol':'anyconnect'})
    pipe.request('disconnect')
    deadline=time.monotonic()+10
    while pipe.request('status')['vpn']['state']!='disconnected':
        assert time.monotonic()<deadline,'Cancel did not finish';time.sleep(.1)
    report['connect_and_cancel_while_blocked']='passed'
    pipe.request('firewall',{'enabled':False});pipe.settled(False)
    assert external(),'OFF did not restore IPv4 access'
    # Run real username/password authentication, CSTP, Wintun address setup,
    # and a bidirectional UDP packet through that adapter, while protection is ON.
    from mock_anyconnect import MockAnyConnect
    fixture=MockAnyConnect(root/'build/windows-fixture',runtime)
    pipe.events.clear()
    pipe.request('firewall',{'enabled':True,'gateway':fixture.url});pipe.settled(True)
    pipe.request('connect',{'gateway':fixture.url,'protocol':'anyconnect','legacyAuth':True,'tls12Only':True,'disableUdp':True})
    deadline=time.monotonic()+45
    while True:
        state=pipe.request('status')
        events,pipe.events=pipe.events,[]
        for event in events:
            if event.get('event')=='auth':
                answer='fixture-only' if event.get('secret') else 'ci-user'
                pipe.request('auth',{'challenge':event['challenge'],'accepted':True,'answer':answer})
            elif event.get('event')=='error':raise AssertionError('Fixture VPN: '+event.get('message',''))
        if state['vpn']['state']=='connected':break
        assert time.monotonic()<deadline,'Fixture VPN did not connect: '+json.dumps(state)
        time.sleep(.1)
    assert fixture.authenticated.is_set() and fixture.cstp.is_set()
    assert state['firewall']['tunnel'], 'Connected VPN lacks verified adapter permission'
    # Netsh can return before Windows finishes Duplicate Address Detection.
    # Retry a bounded period on the same verified tunnel; never relax filtering.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
        probe.settimeout(1);deadline=time.monotonic()+8
        while True:
            try:
                probe.sendto(b'OpenConnect Wintun data-path QA',('192.0.2.1',12345))
                payload,peer=probe.recvfrom(512);break
            except OSError:
                if time.monotonic()>=deadline:raise
                time.sleep(.2)
        assert payload==b'OpenConnect Wintun data-path QA' and peer==('192.0.2.1',12345)
    assert fixture.data.wait(1) and not external(), 'Tunnel or outside routing policy failed'
    report['username_password_cstp_wintun_udp']='passed with local TLS fixture'
    pipe.request('disconnect')
    deadline=time.monotonic()+10
    while pipe.request('status')['vpn']['state']!='disconnected':
        assert time.monotonic()<deadline;time.sleep(.1)
    assert not external(), 'Disconnect removed protection'
    pipe.request('firewall',{'enabled':False});pipe.settled(False)
    fixture.close();fixture=None
    # A fresh ON without a profile must also work.
    pipe.request('firewall',{'enabled':True,'gateway':''});pipe.settled(True)
    assert not external()
    pipe.close();pipe=None
    run(runtime,'--stop-service')
    assert not external(),'Stopping the service removed persistent blocking'
    run(runtime,'--install-service');run(runtime,'--service-ready')
    pipe=Pipe();pipe.settled(True)
    report['service_restart_preserves_on']='passed'
    # An open GUI locks its EXE/DLLs. Refuse an update before stopping the
    # service, preserving the current PID, protection and installed files.
    service_pid=pipe.request('status')['service']['pid']
    gui=subprocess.Popen([str(runtime)],env=clean)
    time.sleep(3);assert gui.poll() is None
    guarded=subprocess.run([str(installer),'/S'],capture_output=True,text=True,errors='replace',timeout=45)
    assert guarded.returncode!=0,'Update accepted a running interface'
    run(runtime,'--service-ready')
    assert pipe.settled(True)['service']['pid']==service_pid
    assert not external() and gui.poll() is None
    report['upgrade_with_open_gui']='refused before stopping service; ON retained'
    gui.terminate();gui.wait(10);gui=None
    # Execute the actual installer again with ON, retaining blocking and intent.
    pipe.close();pipe=None
    run(installer,'/S',timeout=90)
    pipe=Pipe();pipe.settled(True);assert not external()
    report['installer_upgrade_preserves_on']='passed'
    pipe.close();pipe=None
    run(runtime,'--recover-killswitch',timeout=45)
    run(runtime,'--service-ready')
    pipe=Pipe();pipe.settled(False);assert external()
    report['administrator_recovery']='passed; service restarted with OFF saved'
    pipe.request('firewall',{'enabled':True,'gateway':''});pipe.settled(True)
    assert not external()
    pipe.request('firewall',{'enabled':False});pipe.settled(False)
    assert external();report['explicit_off_restores_network']='passed'
    pipe.request('firewall',{'enabled':True,'gateway':''});pipe.settled(True)
    assert not external()
    pipe.close();pipe=None
    # Run a byte-identical copy outside the installation directory, as NSIS
    # normally does, so the uninstaller can remove its original executable too.
    uninstall=root/'build/uninstall-check.exe'
    shutil.copy2(runtime.parent/'Uninstall.exe',uninstall)
    # NSIS requires _?= to be the final UNQUOTED command-line tail, including
    # spaces. list2cmdline would quote it and make NSIS spawn a background copy.
    # UCRT Python may stringify paths with '/'; NSIS validates drive roots as
    # C:\\, so the _?= argument must use native backslashes.
    command='"'+str(uninstall).replace('/','\\')+'" /S _?='+str(runtime.parent).replace('/','\\')
    # Removal with a running GUI must leave the service and ON policy intact.
    gui=subprocess.Popen([str(runtime)],env=clean)
    time.sleep(3);assert gui.poll() is None
    guarded=subprocess.run(command,capture_output=True,text=True,errors='replace',timeout=45)
    assert guarded.returncode!=0,'Removal accepted a running interface'
    run(runtime,'--service-ready')
    pipe=Pipe();pipe.settled(True)
    assert not external() and gui.poll() is None
    pipe.close();pipe=None
    report['uninstall_with_open_gui']='refused before stopping service; ON retained'
    gui.terminate();gui.wait(10);gui=None
    removed=subprocess.run(command,capture_output=True,text=True,errors='replace',timeout=60)
    assert removed.returncode==0,'Uninstaller failed ('+str(removed.returncode)+'): '+removed.stderr[-2000:]
    assert not data.exists(),'Uninstall left service data'
    assert not runtime.parent.exists(),'Uninstall left installed runtime files'
    service=subprocess.run(['sc.exe','query','OpenConnectKillSwitch'],capture_output=True,text=True,errors='replace',timeout=10)
    assert service.returncode==1060,'Uninstall left its Windows service: '+service.stdout
    assert external(),'Uninstall did not leave network available'
    run('powershell.exe','-NoProfile','-NonInteractive','-Command',
        "if (!(Get-NetFirewallRule -Name '"+foreign+"' -ErrorAction Stop)) { exit 1 }")
    report['unrelated_firewall_rule']='retained'
    report['uninstall_and_recovery']='passed'
    report['complete']=True
    marker.write_text('complete')
except BaseException:
    # This runs only in a disposable CI account. Print bounded service/ACL
    # diagnostics without credentials, HTTP bodies or the fixture private key.
    for args in [('sc.exe','query','OpenConnectKillSwitch'),('icacls.exe',str(runtime.parent)),
                 ('powershell.exe','-NoProfile','-NonInteractive','-Command',
                  "Get-NetIPAddress -IPAddress 192.0.2.2 -ErrorAction SilentlyContinue | Format-List; Get-NetRoute -DestinationPrefix '192.0.2.0/24' -ErrorAction SilentlyContinue | Format-List")]:
        try:
            result=subprocess.run(args,capture_output=True,text=True,errors='replace',timeout=20)
            print('CI diagnosis:',pathlib.Path(args[0]).name,result.returncode,result.stdout[-4000:],result.stderr[-4000:])
        except (OSError,subprocess.TimeoutExpired) as error:print(type(error).__name__)
    if (data/'service.log').exists():print((data/'service.log').read_text(errors='replace')[-5000:])
    if (data/'tmp/vpnc.log').exists():print((data/'tmp/vpnc.log').read_text(errors='replace')[-6000:])
    raise
finally:
    if gui and gui.poll() is None:
        gui.terminate();gui.wait(10)
    if fixture:fixture.close()
    if existing:existing.close()
    if pipe:pipe.close()
    if runtime.exists():
        if (runtime.parent/'installer.log').exists():
            shutil.copy2(runtime.parent/'installer.log',root/'dist/windows-installer.log')
        try:run(runtime,'--recover-killswitch',timeout=45)
        except (AssertionError,subprocess.TimeoutExpired) as error:print('Recovery diagnosis:',str(error))
        finally:
            if (data/'service.log').exists():shutil.copy2(data/'service.log',root/'dist/windows-service.log')
    marker.write_text('finished')
    if watchdog:watchdog.wait(5)
    subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
        "Remove-NetFirewallRule -Name '"+foreign+"' -ErrorAction SilentlyContinue"],capture_output=True,timeout=15)
    (root/'dist/windows-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
