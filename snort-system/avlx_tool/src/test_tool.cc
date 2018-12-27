#include "pcapparse.h"

#include <memory>
#include <string>
#include "avlx.h"
using string = std::string;

using namespace std;

//! 命中
#define HIT_SUCCESS 0
//! 未命中
#define HIT_FAILED 1
//! rules file 错误
#define RULES_FILES_ERROR 2

//！输入参数错误
#define PARAMETER_ERROR 3

int test_pcap(const char *pcapFile, const char *rulefile) {
    {
        int ret = 0;
        uint64_t rid;
        Benchmark bm;
        bm.readStreams(pcapFile);
    
        auto h = avlx_core_init();

        AVLXCompilerError c_err;
        auto c_ret = avlx_compile_file(h, rulefile, &c_err);
        if(c_ret == AVLX_COMPILE_FAILED) {
            cout << __FILE__ << ":" << __LINE__ << ":"
                 << "open rules failed"
                 << std::endl;
            return RULES_FILES_ERROR;
        }
                                    
        cout << "===========[ PREPARED: " << rulefile << " ]============" << endl;
        auto &packets = bm.packets;
        auto &ipprotos = bm.ipprotos;

        cout << packets.size() <<endl; 
        for (size_t i = 0; i != packets.size(); ++i) {
            const std::string &pkt = packets[i];
            int ipproto = ipprotos[i];

            cout << "ipproto = " << ipproto <<endl;
            switch (ipproto){
                case 1:
                    {
                        TCPMeta tcp_meta;
                         
                        tcp_meta.payload = pkt.c_str();
                        tcp_meta.len = pkt.length();                        
                        // cout << tcp_meta.payload <<endl;
                        // cout << tcp_meta.len <<endl;
                                                  
                        rid = avlx_match_tcp(h, &tcp_meta);
                        break;
                    }
                    case 2:
                    {
                        UDPMeta udp_meta;
                         
                        udp_meta.payload = pkt.c_str();
                        udp_meta.len = pkt.length();
                        rid = avlx_match_udp(h, &udp_meta);
                    }
                        break;
                    default:
                        break;
                 }
                     
            if (rid) {
                cout << __FILE__ << ":" << __LINE__ << ":"
                     << "hit rules"
                     << ":" << avlx_get_sid(h, rid) << ":" << avlx_get_msg(h, rid)
                     << endl;
              ret =  HIT_SUCCESS;
            } else {
                cout << "pcapfile Not hit" << endl;
              ret =  HIT_FAILED;
            }

        }
        avlx_core_free(h);
        return ret;
    } 
}

int test_rules(const char *rulefile) {
    auto h = avlx_core_init();
    
    AVLXCompilerError c_err;
    auto c_ret = avlx_compile_file(h, rulefile, &c_err);

    if(c_ret == AVLX_COMPILE_FAILED) {
    cout << "Rule files are not supported" << endl;
    return c_ret;
  }
  cout << "Rule files are supported" << endl;
  avlx_core_free(h);
  return c_ret;
}


int main (int argc,char **argv) {

    int ret;
    string rulesfile, pcapfile;
    char ** temp = argv;  /* 保留argv */
    int i=0;
    switch (argc){
        case 2:
        {
            while( *temp != NULL ){
                if (1 == i){
                   rulesfile = *temp;
                }
                
                cout<<i++<<": "<<*temp<<endl;
                ++temp;
            }
            ret = test_rules(rulesfile.data());
        }
        break;
        case 3:
        {
            while( *temp != NULL ){
                if (1 == i){
                   rulesfile = *temp;
                }
                if (2 == i){
                   pcapfile  = *temp;
                }
                cout<<i++<<": "<<*temp<<endl;
                ++temp;
            }
            ret = test_pcap(pcapfile.data(), rulesfile.data());
            break;
        }
        default:
        cout << " Parameter error, please refer to README.txt" << endl;
        return PARAMETER_ERROR;

    }
    
    return ret;
}
