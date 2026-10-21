// SPDX-License-Identifier: GPL-2.0-or-later
#include "WindowsDnsBootstrap.h"
#include <QElapsedTimer>
#include <QHostAddress>
#include <QNetworkDatagram>
#include <QRandomGenerator>
#include <QSet>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QUrl>
#include <QtEndian>
#ifdef Q_OS_WIN
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#endif
#include <memory>
#include <cstring>
#include <vector>

namespace {
quint16 word(const QByteArray& data,int offset){return qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(data.constData()+offset));}
void append(QByteArray& data,quint16 value){char bytes[2];qToBigEndian(value,reinterpret_cast<uchar*>(bytes));data.append(bytes,2);}
bool name(const QByteArray& wire,int& position,QString& value)
{
    int at=position,after=-1;QByteArray result;QSet<int> seen;
    for(int steps=0;steps<128;++steps){
        if(at<0||at>=wire.size()||seen.contains(at))return false;seen.insert(at);
        const auto length=uchar(wire.at(at++));
        if((length&0xc0)==0xc0){
            if(at>=wire.size())return false;
            if(after<0)after=at+1;at=((length&0x3f)<<8)|uchar(wire.at(at));continue;
        }
        if(length&0xc0||length>63||at+length>wire.size())return false;
        if(!length){position=after<0?at:after;value=QString::fromLatin1(result).toLower();return result.size()<=253;}
        if(!result.isEmpty())result+='.';result+=wire.mid(at,length);at+=length;
    }
    return false;
}
QByteArray query(const QString& host,quint16 type,quint16 id)
{
    const auto ascii=QUrl::toAce(host);if(ascii.isEmpty()||ascii.size()>253)return {};
    QByteArray data;append(data,id);append(data,0x100);append(data,1);append(data,0);append(data,0);append(data,0);
    for(const auto& part:ascii.split('.')){if(part.isEmpty()||part.size()>63)return {};data+=char(part.size());data+=part;}
    data+='\0';append(data,type);append(data,1);return data;
}
QByteArray tcp(const QHostAddress& server,const QByteArray& request)
{
    QTcpSocket socket;socket.connectToHost(server,53);if(!socket.waitForConnected(300))return {};
    QByteArray frame;append(frame,quint16(request.size()));frame+=request;
    if(socket.write(frame)!=frame.size())return {};
    QElapsedTimer timer;timer.start();QByteArray result;int expected=-1;
    while(timer.elapsed()<800){
        if(socket.bytesAvailable())result+=socket.readAll();
        if(result.size()>=2&&expected<0){expected=word(result,0);if(expected<12||expected>8192)return {};}
        if(expected>=0&&result.size()>=expected+2)return result.mid(2,expected);
        socket.waitForReadyRead(40);
    }
    return {};
}
}

QStringList WindowsDnsBootstrap::systemServers()
{
#ifdef Q_OS_WIN
    ULONG length=16384;std::vector<uchar> data(length);
    ULONG result=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST,nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(data.data()),&length);
    if(result==ERROR_BUFFER_OVERFLOW){data.resize(length);result=GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST|GAA_FLAG_SKIP_MULTICAST,nullptr,reinterpret_cast<IP_ADAPTER_ADDRESSES*>(data.data()),&length);}
    if(result!=NO_ERROR)return {};
    QStringList addresses;
    for(auto adapter=reinterpret_cast<IP_ADAPTER_ADDRESSES*>(data.data());adapter;adapter=adapter->Next){
        if(adapter->OperStatus!=IfOperStatusUp)continue;
        for(auto server=adapter->FirstDnsServerAddress;server;server=server->Next){
            QHostAddress ip;const auto address=server->Address.lpSockaddr;if(!address)continue;
            if(address->sa_family==AF_INET)ip.setAddress(ntohl(reinterpret_cast<sockaddr_in*>(address)->sin_addr.s_addr));
            else if(address->sa_family==AF_INET6){const auto v6=reinterpret_cast<sockaddr_in6*>(address);
                Q_IPV6ADDR bytes;std::memcpy(bytes.c,&v6->sin6_addr,16);ip.setAddress(bytes);
                if(v6->sin6_scope_id)ip.setScopeId(QString::number(v6->sin6_scope_id));}
            if(!ip.isNull()&&!ip.isMulticast()&&!addresses.contains(ip.toString()))addresses<<ip.toString();
            if(addresses.size()==8)return addresses;
        }
    }
    return addresses;
#else
    return {}; // Parser tests are portable; Windows owns resolver discovery.
#endif
}

QStringList WindowsDnsBootstrap::response(const QByteArray& wire,quint16 id,const QString& host,quint16 type,bool& truncated)
{
    truncated=false;
    if(wire.size()<12||wire.size()>8192||word(wire,0)!=id||(word(wire,2)&0xf80f)!=0x8000||word(wire,4)!=1)return {};
    int at=12;QString question;
    if(!name(wire,at,question)||question!=QString::fromLatin1(QUrl::toAce(host)).toLower()
        ||at+4>wire.size()||word(wire,at)!=type||word(wire,at+2)!=1)return {};
    truncated=word(wire,2)&0x200;if(truncated)return {};
    at+=4;const auto count=word(wire,6);if(count>128)return {};
    struct Record{QString owner,target,address;};QList<Record> records;
    for(int index=0;index<count;++index){
        QString owner;if(!name(wire,at,owner)||at+10>wire.size())return {};
        const auto kind=word(wire,at),cls=word(wire,at+2),length=word(wire,at+8);at+=10;
        if(at+length>wire.size())return {};
        Record record;record.owner=owner;
        if(cls==1&&kind==5){int offset=at;if(!name(wire,offset,record.target)||offset!=at+length)return {};}
        else if(cls==1&&kind==type&&kind==1&&length==4)record.address=QHostAddress(qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(wire.constData()+at))).toString();
        else if(cls==1&&kind==type&&kind==28&&length==16){Q_IPV6ADDR address;std::memcpy(address.c,wire.constData()+at,16);record.address=QHostAddress(address).toString();}
        records<<record;at+=length;
    }
    QSet<QString> aliases{question};
    for(int depth=0;depth<16;++depth){const auto before=aliases.size();for(const auto& record:records)
        if(aliases.contains(record.owner)&&!record.target.isEmpty())aliases.insert(record.target);
        if(aliases.size()==before)break;}
    QStringList result;for(const auto& record:records){QHostAddress ip(record.address);
        if(aliases.contains(record.owner)&&!ip.isNull()&&!ip.isLoopback()&&!ip.isMulticast())result<<ip.toString();}
    result.removeDuplicates();return result;
}

QStringList WindowsDnsBootstrap::lookup(const QString& host,const QStringList& servers,QString& error)
{
    struct Pending{QHostAddress server;quint16 id,type;QByteArray request;std::unique_ptr<QUdpSocket> socket;bool done=false;};
    std::vector<Pending> pending;
    for(const auto& value:servers.mid(0,4))for(quint16 type:{quint16(1),quint16(28)}){
        Pending item;item.server=QHostAddress(value);item.id=quint16(QRandomGenerator::system()->generate());item.type=type;
        item.request=query(host,type,item.id);item.socket=std::make_unique<QUdpSocket>();
        if(item.server.isNull()||item.request.isEmpty())continue;
        if(!item.socket->bind(item.server.protocol()==QAbstractSocket::IPv4Protocol?QHostAddress::AnyIPv4:QHostAddress::AnyIPv6,0))continue;
        if(item.socket->writeDatagram(item.request,item.server,53)<0)continue;pending.push_back(std::move(item));
    }
    QElapsedTimer timer;timer.start();QStringList addresses;
    while(timer.elapsed()<2500){bool unfinished=false;
        for(auto& item:pending){if(item.done)continue;unfinished=true;
            if(!item.socket->hasPendingDatagrams())item.socket->waitForReadyRead(15);
            while(item.socket->hasPendingDatagrams()){
                const auto datagram=item.socket->receiveDatagram(8192);
                if(datagram.senderAddress()!=item.server||datagram.senderPort()!=53)continue;
                bool truncated=false;auto found=response(datagram.data(),item.id,host,item.type,truncated);
                if(truncated){bool ignored=false;found=response(tcp(item.server,item.request),item.id,host,item.type,ignored);}
                if(!found.isEmpty()){addresses<<found;item.done=true;}
            }
        }
        if(!unfinished)break;
    }
    addresses.removeDuplicates();if(addresses.isEmpty())error="VPN hostname could not be resolved through the system DNS servers";
    return addresses;
}
