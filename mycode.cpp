#include<bits/stdc++.h>

using namespace std;

#define ui unsigned int

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
    // void set_bits(char * buff, param &par, int offset){
    //     int charSize = sizeof(buff[0])*8;
    //     int section = offset/(charSize);
    //     int charOff = charSize - offset%charSize - 1;
    //     int cur = par.len-1;
    //     int fromPointer = min(7, par.len - 1);
    //     int fromCounter = 0;
    //     int fromByte = 1;
    //     while(cur >= 0){
    //         copyBit(par.val, fromPointer, buff[section], charOff);
    //         charOff--;
    //         if(charOff < 0){
    //             charOff = charSize - 1;
    //             section++;
    //         }
    //         cur--;
    //         fromCounter++;
    //         fromPointer--;
    //         if(fromCounter == 8){
    //             fromCounter = 0;
    //             fromByte++;
    //             fromPointer = min(fromByte*8 - 1, par.len-1);
    //         }
    //     }
    // }

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
            // cout << (unsigned int)raw[icmp_pos] << " ?? " << (unsigned int)raw[icmp_pos+1] << "--\n";
            check_sum += ((int)raw[icmp_pos+1])*256 + (int)raw[icmp_pos];
            // cout << check_sum << "-";
            icmp_pos += 2;
        }

        // cout << (unsigned short) (~check_sum) << "------\n";        

        if(icmp_pos < total_len.val){
            check_sum += raw[icmp_pos]*256;
        }
        check_sum = (check_sum >> 16) + (check_sum & 0xffff);
        check_sum += (check_sum >> 16);
        icmp_checksum.val = (unsigned short) (~check_sum);
        // cout << (unsigned short) (~check_sum) << "------\n";

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

int main(){
    ICMP_Packet icmp;
    int length = 1000;
    char * buff = new char[length]; 

    icmp.type.val = 3;
    icmp.code.val = 1;
    icmp.icmp_checksum.val = 0;

    icmp.version.val = 4;
    icmp.header_len.val = 5;
    icmp.ttl.val = 20;
    icmp.source_addr.val = strToIp("16.1.1.1");
    icmp.dest_addr.val = strToIp("15.1.1.1");
    icmp.protocol.val = 1;
    cout << "Ashche\n";
    icmp.construct_packet(buff, length);
    cout << icmp.total_len.val << "==========\n";
    for(int i = 0; i < icmp.total_len.val; i++){
        cout << (unsigned int)buff[i] << " ";
    }
    cout << "Hello world\n";
}