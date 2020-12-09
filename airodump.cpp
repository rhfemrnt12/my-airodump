#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/in.h>

struct radiotap_header {
        u_int8_t        it_version;
        u_int8_t        it_pad;
        u_int16_t       it_len;
        u_int32_t       it_present1;
        u_int32_t       it_present2;
        u_int8_t        flags;
        u_int8_t        rate;
        u_int16_t       chan_freq;
        u_int16_t       chan_flags;
        u_int8_t        antsignal_1;
        u_int8_t        padding;
        u_int16_t       rx_flags;
        u_int8_t        antsignal_2;
        u_int8_t        ant;
};

struct beacon_header{
    u_int16_t type;
    u_int16_t type_padding;
    u_int8_t d_addr[6];
    u_int8_t s_addr[6];
    u_int8_t BSSID[6];
    u_int16_t number;
};

struct wireless_header{
    u_int8_t timestamp[8];
    u_int16_t beacon_interval;
    u_int16_t capabilties_info;
    u_int8_t tag_num;
    u_int8_t ssid_len;
};

struct probe_header{
    u_int8_t tag_num;
    u_int8_t ssid_len;
};

void usage(){
    printf("syntax: test <interface>\n");
    printf("sample: test mon0\n");
}

u_int8_t handle_antsignal(u_int8_t anti_sig){
    u_int8_t n;
    n = ~anti_sig;
    n += 1;
    return n;
}

int main(int argc, char* argv[]){

    if (argc != 2) {
        usage();
        return -1;
    }

    struct radiotap_header* r_hdr;
    struct beacon_header* b_hdr;
    struct wireless_header* w_hdr;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    printf("BSSID\t\t\tPWR\t\tBeacons\t\t\tESSID\n");

    while(true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        r_hdr = (struct radiotap_header*)packet;
        b_hdr = (struct beacon_header*)(packet+r_hdr->it_len);
        w_hdr = (struct wireless_header*)(packet+r_hdr->it_len+sizeof(struct beacon_header));
        packet = packet + r_hdr->it_len+sizeof(struct beacon_header)+sizeof(struct wireless_header);
        handle_antsignal(r_hdr->antsignal_1);

        if(b_hdr->type == 0x0080){
            printf("%02x:%02x:%02x:%02x:%02x:%02x\t", b_hdr->BSSID[0], b_hdr->BSSID[1], b_hdr->BSSID[2], b_hdr->BSSID[3], b_hdr->BSSID[4], b_hdr->BSSID[5]);
            printf("-%d\t\t",handle_antsignal(r_hdr->antsignal_1));
            printf("%d\t\t\t",b_hdr->type);

            for(int i = 0; i<w_hdr->ssid_len; i++){
                        printf("%c", packet[i]);
            }
            printf("\t");
            printf("\n");
        }
    }
    printf("\n\n");

    pcap_close(handle);
}