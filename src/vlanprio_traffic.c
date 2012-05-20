/*
 ============================================================================
 Name        : vlanprio_traffic.c
 Author      : Andre
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <libnet.h>
#include <libnet/libnet-asn1.h>
#include <libnet/libnet-functions.h>
#include <libnet/libnet-headers.h>
#include <libnet/libnet-macros.h>
#include <libnet/libnet-structures.h>
#include <libnet/libnet-types.h>


#define BASE_DECIMAL 10
#define libnet_timersub(tvp, uvp, vvp)                                  \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)

static void usage(char *name) {
    fprintf(stderr, "usage %s -v [vlan-id] -q [vlan-prio] -a [srcMAC] -b [dstMac] -d [dstIP.oprt] -s [srcIP.port] "
    		"-p [payload size] -t [rate (us)] -i [interface] \n", name);
}

int main(int argc, char *argv[]) {

	printf("started\n");

	libnet_t *lnet;
	char * pEnd = NULL;
    char *host_dst = "2.2.2.2";
    char *host_src = "1.1.1.1";
	int len;
	int rate;
	char *eth_device = NULL;
	char errbuf[LIBNET_ERRBUF_SIZE];
    struct timeval delta_time;
    struct timeval start_time;
    struct timeval curr_time;
    struct timeval end_time;

	// layer 2
	libnet_ptag_t vlan_ptag = 0;
	u_int8_t vlan_cfi_flag = 0;
	u_char* mac_dst, *mac_src;
	u_int8_t *vlan_payload = NULL;
	u_int32_t vlan_payload_s = 0;
	u_int8_t vlan_prio;
	u_int16_t vlan_id;

	// layer 3
	libnet_ptag_t ip_ptag = 0;
	u_int8_t  ip_tos  = 0;
	u_int8_t  ip_id   = 0;
	u_int8_t  ip_frag = 0;
	u_int8_t  ip_ttl  = 64;
	u_short   ip_proto = IPPROTO_UDP;
	u_int16_t ip_chksum = 0;
	u_int8_t *ip_payload = NULL;
	u_int32_t ip_payload_s = 0;
	u_int32_t ip_src;
	u_int32_t ip_dst;

	// layer 4
	libnet_ptag_t udp_ptag = 0;
	u_int16_t udp_checksum = 0;
	u_int16_t udp_src_prt;
	u_int16_t udp_dst_prt;
	u_int8_t *udp_payload;   // ==> user payload
	u_int32_t udp_payload_s;

	//====================================================================
	/*
	 *  Initialize the library.  Root priviledges are required.
	 */

	printf("parse input\n");
    u_char *cp;
	int c;
    while ((c = getopt(argc, argv, "v:q:a:b:d:s:p:i:t:")) != EOF)
    {
        switch (c)
        {
        	case 'v':
        		vlan_id = strtol(optarg,pEnd,BASE_DECIMAL);
        		if ( vlan_id < 1 || vlan_id > 4096 ) {
        			fprintf(stderr, "invalid vlan-id: %s\n",optarg);
        			return (EXIT_FAILURE);
        		}
        		printf("v: vlan-id=%d\n",vlan_id);
        		break;

        	case 'q': // vlan-prio (tx-Queue)
        		vlan_prio = strtol(optarg,pEnd,BASE_DECIMAL);
        		if ( vlan_prio < 0 || vlan_prio > 7 ) {
        			fprintf(stderr, "invalid vlan-prio: %s\n",optarg);
        			return (EXIT_FAILURE);
        		}
        		printf("q: vlan-prio=%d\n",vlan_prio);
        		break;

        	case 'a': // source-mac
        		mac_src = libnet_hex_aton(optarg, &len);
        		printf("b: mac_src=[%02X:%02X:%02X:%02X:%02X:%02X]\n",
        				mac_src[0],mac_src[1],mac_src[2],mac_src[3],mac_src[4],mac_src[5]);
        		break;

        	case 'b':  // dest-mac
        		mac_dst = libnet_hex_aton(optarg, &len);
        		printf("b: mac_dst=[%02X:%02X:%02X:%02X:%02X:%02X]\n",
        				mac_dst[0],mac_dst[1],mac_dst[2],mac_dst[3],mac_dst[4],mac_dst[5]);
        		break;

        	case 's': // source-ip
    			if (!(cp = strrchr(optarg, '.'))) {
    				usage(argv[0]);
    			}
    			*cp++ = 0;
    			udp_src_prt = (u_int16_t) strtol(cp,pEnd,BASE_DECIMAL);
    			host_src = optarg;
        		printf("s: udp_src_prt=%d, ip_src=%s\n",udp_src_prt,optarg);
    			break;

        	case 'd': // dest-ip
    			if (!(cp = strrchr(optarg, '.'))) {
    				usage(argv[0]);
    			}
    			*cp++ = 0;
    			udp_dst_prt = (u_int16_t) strtol(cp,pEnd,BASE_DECIMAL);
    			host_dst = optarg;
        		printf("d: udp_dst_prt=%d, ip_dst=%s\n",udp_dst_prt,optarg);
        		break;

        	case 'i': // interface
        		eth_device = optarg;
        		printf("i: eth_device=%s\n",eth_device);
        		break;

            case 'p':
            	udp_payload_s = strtol(optarg,pEnd,BASE_DECIMAL);
        		printf("p: udp_payload_s=%d\n",udp_payload_s);
                break;

            case 't':
            	rate = strtol(optarg,pEnd,BASE_DECIMAL);
        		printf("p: rate=%d\n",rate);
                break;

            default:
				usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

	printf("init libnet\n");
	lnet = libnet_init(LIBNET_LINK, eth_device, errbuf);
	if (lnet == NULL) {
		fprintf(stderr, "libnet_init() failed: %s", errbuf);
		exit(EXIT_FAILURE);
	}
	printf("build packet\n");

	//=====================================================================
	printf("libnet_build_udp\n");
	int j = 0;
	u_char payload[udp_payload_s];
	for (j = 0; j < udp_payload_s; j++) {
		payload[j] = libnet_get_prand(LIBNET_PR8);
	}
	udp_payload = &payload[0];

	u_int32_t udp_pkt_len = LIBNET_UDP_H + udp_payload_s;
    udp_ptag = libnet_build_udp(udp_src_prt, udp_dst_prt, udp_pkt_len,
    							udp_checksum, udp_payload, udp_payload_s,
    							lnet, 0);
    if (udp_ptag == -1) {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(lnet));
        goto bad;
    }

	//=====================================================================
	printf("libnet_build_ipv4\n");
	u_int16_t ip_hdr_len = LIBNET_IPV4_H + udp_pkt_len;

	if ((ip_dst = libnet_name2addr4(lnet, host_dst, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		exit(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, host_src, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		exit(EXIT_FAILURE);
	}

	ip_ptag = libnet_build_ipv4(ip_hdr_len, ip_tos, ip_id, ip_frag, ip_ttl,
    							ip_proto, ip_chksum, ip_src, ip_dst, ip_payload, ip_payload_s,
    							lnet, 0);
	if (ip_ptag == -1) {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(lnet));
		goto bad;
	}

	//====================================================================
	printf("libnet_build_802_1q\n");
	vlan_ptag = libnet_build_802_1q(mac_dst, mac_src,
			ETHERTYPE_VLAN, vlan_prio, vlan_cfi_flag, vlan_id,
			ETHERTYPE_IP  , vlan_payload, vlan_payload_s,
			lnet, 0);
	if (vlan_ptag == -1) {
		fprintf(stderr, "Can't build 802.1q header: %s\n", libnet_geterror(lnet));
		goto bad;
	}


	//=====================================================================
	/*
	 *  Write it to the wire.
	 */
	printf("libnet_write, packet_size=%d\n",libnet_getpacket_size(lnet));
	int repeat = 0;
	u_int16_t udp_prio_src_prt = udp_src_prt;
	u_int16_t udp_prio_dst_prt = udp_dst_prt;
    gettimeofday(&start_time, NULL);

	for (repeat = 0; repeat < 10; ++repeat) {
		int32_t bytes_written = libnet_write(lnet);
		if (bytes_written == -1) {
			fprintf(stderr, "Write error: %s\n", libnet_geterror(lnet));
			goto bad;
		}

		// modify packet
		if (vlan_prio == 7) {
			vlan_prio = 0;
			udp_prio_src_prt = udp_src_prt + vlan_prio;
			udp_prio_dst_prt = udp_dst_prt + vlan_prio;
		} else {
			vlan_prio++;
			udp_prio_src_prt = udp_prio_src_prt++;
			udp_prio_dst_prt = udp_prio_dst_prt++;
		}

	    udp_ptag = libnet_build_udp(udp_prio_src_prt, udp_prio_dst_prt, udp_pkt_len,
	    							udp_checksum, udp_payload, udp_payload_s,
	    							lnet, udp_ptag);

		vlan_ptag = libnet_build_802_1q(mac_dst, mac_src,
				ETHERTYPE_VLAN, vlan_prio, vlan_cfi_flag, vlan_id,
				ETHERTYPE_IP, vlan_payload, vlan_payload_s,
				lnet, vlan_ptag);

		usleep(rate);
	}

    gettimeofday(&end_time, NULL);

    libnet_timersub(&end_time, &start_time, &delta_time);
    fprintf(stderr, "Total time spent in loop: %d.%d\n", delta_time.tv_sec, delta_time.tv_usec);

    struct libnet_stats ls;
    libnet_stats(lnet, &ls);
    fprintf(stderr, "Packets sent:  %lld\n"
                    "Packet errors: %lld\n"
                    "Bytes written: %lld\n",
                    ls.packets_sent, ls.packet_errors, ls.bytes_written);


	libnet_destroy(lnet);
	return (EXIT_SUCCESS);

	bad: {
		libnet_destroy(lnet);
		return (EXIT_FAILURE);
	}

}
