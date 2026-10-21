#!/usr/bin/env python3
"""Local TLS/CSTP fixture for an actual Wintun data-path test, without a VPN account.

The generated CA is added ONLY to a disposable runner's installed copy. Never
to the staged artifact, source tree, or operating system's certificate store.
This fixture is deliberately not a production VPN server.
"""
import pathlib
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import threading
import urllib.parse


def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535


def udp_reply(packet):
    if len(packet)<28 or packet[0]>>4!=4 or packet[9]!=17:return None
    ihl=(packet[0]&15)*4
    if ihl<20 or len(packet)<ihl+8:return None
    source,destination,length,_=struct.unpack_from('!HHHH',packet,ihl)
    if destination!=12345 or length<8 or ihl+length>len(packet):return None
    payload=packet[ihl+8:ihl+length]
    udp=struct.pack('!HHHH',destination,source,length,0)+payload
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(udp),1,0,64,17,0,packet[16:20],packet[12:16])
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return ip+udp


class MockAnyConnect:
    def __init__(self, directory, runtime):
        self.directory=pathlib.Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.ca=pathlib.Path(runtime).parent/'ca-bundle.crt'
        self.original=self.ca.read_bytes()
        # A local NIC address is a valid selected gateway; no public listener is opened.
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1',9));self.host=probe.getsockname()[0]
        cert=self.directory/'fixture-cert.pem';key=self.directory/'fixture-key.pem'
        subprocess.run([shutil.which('openssl'),'req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','1',
            '-keyout',str(key),'-out',str(cert),'-subj','/CN=OpenConnect disposable CI fixture',
            '-addext','subjectAltName=IP:'+self.host,
            '-addext','basicConstraints=critical,CA:TRUE'],check=True,capture_output=True,timeout=20)
        self.ca.write_bytes(self.original+b'\n'+cert.read_bytes())
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        fixture=self
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address=True;daemon_threads=True
            def get_request(self):
                sock,peer=super().get_request()
                return context.wrap_socket(sock,server_side=True),peer
            def handle_error(self,request,address):pass # No bodies, keys or credentials in CI logs.
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(35);stream=self.request.makefile('rb')
                while True:
                    line=stream.readline(8192)
                    if not line:return
                    method,path,_=line.decode('ascii').strip().split(' ',2)
                    headers={}
                    for _ in range(100):
                        line=stream.readline(8192)
                        if line in (b'\r\n',b'\n'):break
                        name,value=line.decode('latin1').split(':',1);headers[name.lower()]=value.strip()
                    size=int(headers.get('content-length','0'))
                    if size>65536:return
                    body=stream.read(size)
                    if method=='CONNECT':
                        assert 'ci-session' in headers.get('cookie','')
                        self.request.sendall(b'HTTP/1.1 200 CONNECTED\r\nX-CSTP-Version: 1\r\nX-CSTP-MTU: 1406\r\n'
                            b'X-CSTP-Address: 192.0.2.2\r\nX-CSTP-Netmask: 255.255.255.0\r\n'
                            b'X-CSTP-Split-Include: 192.0.2.0/255.255.255.0\r\nX-CSTP-Keepalive: 10\r\n\r\n')
                        fixture.cstp.set()
                        while True:
                            header=stream.read(8)
                            if len(header)!=8 or header[:4]!=b'STF\x01':return
                            length,kind,_=struct.unpack('!HBB',header[4:]);payload=stream.read(length)
                            if len(payload)!=length:return
                            if kind==3:self.request.sendall(b'STF\x01\x00\x00\x04\x00')
                            elif kind==0:
                                reply=udp_reply(payload)
                                if reply:
                                    self.request.sendall(b'STF\x01'+struct.pack('!HBB',len(reply),0,0)+reply)
                                    fixture.data.set()
                            elif kind in (5,9):return
                    elif method=='POST':
                        values=urllib.parse.parse_qs(body.decode('ascii'))
                        assert values.get('username')==['ci-user'] and values.get('password')==['fixture-only']
                        fixture.authenticated.set()
                        self.reply(b'<auth id="success"/>',b'Set-Cookie: webvpn=ci-session; Secure; HttpOnly\r\n')
                    else:
                        self.reply(b'<auth id="main"><message>Disposable CI VPN</message><form method="post" action="/">'
                            b'<input type="text" name="username" label="Username:"/>'
                            b'<input type="password" name="password" label="Password:"/></form></auth>')
            def reply(self, body, extra=b''):
                self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nConnection: keep-alive\r\n'+extra+
                    b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body)
        self.authenticated=threading.Event();self.cstp=threading.Event();self.data=threading.Event()
        self.server=Server((self.host,0),Handler)
        self.url='https://'+self.host+':'+str(self.server.server_address[1])
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
    def close(self):
        self.server.shutdown();self.server.server_close();self.ca.write_bytes(self.original)
        shutil.rmtree(self.directory)
