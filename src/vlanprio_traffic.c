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

#include <glib.h>

#define BASE_DECIMAL 10

#define TPID_VLAN_8100          0x8100
#define TPID_VLAN_88A8          0x88a8
#define TPID_VLAN_9100          0x9100
#define TPID_VLAN_9200          0x9200
#define TPID_VLAN_9300          0x9300

#define TPID_VLAN_8100_STR          "0x8100"
#define TPID_VLAN_88A8_STR          "0x88a8"
#define TPID_VLAN_9100_STR          "0x9100"
#define TPID_VLAN_9200_STR          "0x9200"
#define TPID_VLAN_9300_STR          "0x9300"


#define BUFFER_CHAR 256

#define libnet_timersub(tvp, uvp, vvp)                                  \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
                if ((vvp)->tv_usec < 0) {                               \
                        (vvp)->tv_sec--;                                \
                        (vvp)->tv_usec += 1000000;                      \
                }                                                       \
        } while (0)


/*
 ============================================================================
 */
int main(int argc, char *argv[]) {

	printf("=====  started ======\n");

	gchar *interface = "eth0";
	gint svid = 0;
	gint svidprio = -1;
	gboolean svidrotate = FALSE;
	gchar *stpid = "0x8100";
	gint stpid_val = TPID_VLAN_8100;
	gint cvid     = 0;
	gint cvidprio = -1;
	gboolean cvidrotate = FALSE;
	gchar *macsrc = "00:00:00:00:00:00";
	gchar *macdst = "00:00:00:00:00:00";
	gchar *ipdst  = "0.0.0.0.0";
	gchar *ipsrc  = "0.0.0.0.0";
	gint udpsrc = 0;
	gint udpdst = 0;
	gint pktsize = 0;
	gint txrate = 0;
	gint packets = 0;

	GOptionEntry cmd_entries[] = {
		{ "interface"  , 'i', 0, G_OPTION_ARG_STRING , &interface  , "interface", NULL },
		{ "svid"       ,  0 , 0, G_OPTION_ARG_INT    , &svid       , "svlan id [1-4096]", NULL },
		{ "svidprio"   ,  0 , 0, G_OPTION_ARG_INT    , &svidprio   , "svlan priority [0-7]", NULL },
		{ "svidrotate" ,  0 , 0, G_OPTION_ARG_NONE   , &svidrotate , "rotate svlan priority", NULL },
		{ "stpid"      ,  0 , 0, G_OPTION_ARG_STRING , &stpid      , "svlan tpid val [0x8100, 0x88a8, 0x9100, 0x9200, 0x9300]", NULL },
		{ "cvid"       ,  0 , 0, G_OPTION_ARG_INT    , &cvid       , "cvlan id [1-4096]", NULL },
		{ "cvidprio"   ,  0 , 0, G_OPTION_ARG_INT    , &cvidprio   , "cvlan priority [0-7]", NULL },
		{ "cvidrotate" ,  0 , 0, G_OPTION_ARG_NONE   , &cvidrotate , "rotate cvlan priority", NULL },
		{ "macsrc"     ,  0 , 0, G_OPTION_ARG_STRING , &macsrc     , "source mac address", NULL },
		{ "macdst"     ,  0 , 0, G_OPTION_ARG_STRING , &macdst     , "destination mac address", NULL },
		{ "ipsrc"      ,  0 , 0, G_OPTION_ARG_STRING , &ipsrc      , "source IP ", NULL },
		{ "udpsrc"     ,  0 , 0, G_OPTION_ARG_INT    , &udpsrc     , "source UDP port", NULL },
		{ "ipdst"      ,  0 , 0, G_OPTION_ARG_STRING , &ipdst      , "dest IP ", NULL },
		{ "udpdst"     ,  0 , 0, G_OPTION_ARG_INT    , &udpdst     , "dest UDP port", NULL },
		{ "pktsize"    , 's', 0, G_OPTION_ARG_INT    , &pktsize    , "UDP payload size in bytes", NULL },
		{ "txrate"     , 't', 0, G_OPTION_ARG_INT    , &txrate     , "transmission rate in bps", NULL },
		{ "packets"    , 'p', 0, G_OPTION_ARG_INT    , &packets    , "number of packets for tx", NULL },
		{ NULL }
	};

	GError *error = NULL;
	GOptionContext *context;

	context = g_option_context_new("vlan priority traffic generator");
	g_option_context_add_main_entries(context, cmd_entries, NULL);
	if (!g_option_context_parse(context, &argc, &argv, &error)) {
		g_print("option parsing failed: %s\n", error->message);
		exit(EXIT_FAILURE);
	}
	// checks
	if (svid < 1 || svid > 4096) {
		fprintf(stderr, "invalid svid: %d\n", svid);
		return (EXIT_FAILURE);
	}
	if (svidprio < 0 || svidprio > 7) {
		fprintf(stderr, "invalid svidprio: %d\n", svidprio);
		return (EXIT_FAILURE);
	}
	if (cvid < 1 || cvid > 4096) {
		fprintf(stderr, "invalid cvid: %d\n", cvid);
		return (EXIT_FAILURE);
	}
	if (cvidprio < 0 || cvidprio > 7) {
		fprintf(stderr, "invalid cvidprio: %d\n", cvidprio);
		return (EXIT_FAILURE);
	}

	g_ascii_strdown(stpid,strlen(stpid));
	if (g_strcmp0(stpid, TPID_VLAN_8100_STR) == 0) {
		stpid_val = TPID_VLAN_8100;
	} else if (g_strcmp0(stpid, TPID_VLAN_88A8_STR) == 0) {
		stpid_val = TPID_VLAN_88A8;
	} else if (g_strcmp0(stpid, TPID_VLAN_9100_STR) == 0) {
		stpid_val = TPID_VLAN_9100;
	} else if (g_strcmp0(stpid, TPID_VLAN_9200_STR) == 0) {
		stpid_val = TPID_VLAN_9200;
	} else if (g_strcmp0(stpid, TPID_VLAN_9300_STR) == 0) {
		stpid_val = TPID_VLAN_9300;
	} else {
		fprintf(stderr, "invalid stpid: %s\n", stpid);
		return (EXIT_FAILURE);
	}

	g_print("interface   %s\n",interface) ;
	g_print("svid        %d\n",svid) ;
	g_print("svidprio    %d\n",svidprio) ;
	g_print("svidrotate  %d\n",svidrotate) ;
	g_print("stpid       %s\n",stpid) ;
	g_print("cvid        %d\n",cvid) ;
	g_print("cvidprio    %d\n",cvidprio) ;
	g_print("cvidrotate  %d\n",cvidrotate) ;
	g_print("macdst      %s\n",macdst) ;
	g_print("ipdst       %s\n",ipdst) ;
	g_print("udpdst      %d\n",udpdst) ;
	g_print("macsrc      %s\n",macsrc) ;
	g_print("ipsrc       %s\n",ipsrc) ;
	g_print("udpsrc      %d\n",udpsrc) ;
	g_print("pktsize     %d\n",pktsize) ;
	g_print("txrate      %d\n",txrate) ;
    g_print("packets     %d\n",packets) ;

	libnet_t *lnet;
	char *host_dst = "2.2.2.2";
	char *host_src = "1.1.1.1";
	int len;
	int tx_speed_bps;
	char *eth_device = NULL;
	char errbuf[LIBNET_ERRBUF_SIZE];
	struct timeval delta_time;
	struct timeval start_time;
	struct timeval end_time;
	int repeat = 0;
	int repeat_max = 0;
	int rotate_svlan_prio = 0;
	u_int32_t loop_delay = 80;

	// layer 2
	u_char *mac_dst, *mac_src;
	libnet_ptag_t svlan_ptag = 0;
	u_int8_t svlan_cfi_flag = 0;
	u_int8_t *svlan_payload = NULL;
	u_int32_t svlan_payload_s = 0;
	u_int8_t svlan_prio;
	u_int16_t svlan_id;

	// layer 3
	libnet_ptag_t ip_ptag = 0;
	u_int8_t ip_tos = 0;
	u_int8_t ip_id = 0;
	u_int8_t ip_frag = 0;
	u_int8_t ip_ttl = 64;
	u_short ip_proto = IPPROTO_UDP;
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
	u_int8_t *udp_payload; // ==> user payload
	u_int32_t udp_payload_s;


    mac_src = libnet_hex_aton(macsrc, &len);
    mac_dst = libnet_hex_aton(macdst, &len);
    svlan_id = (u_int16_t) svid;
    svlan_prio = (u_int8_t) svidprio;
    udp_src_prt = (u_int16_t) udpsrc;
    udp_dst_prt = (u_int16_t) udpdst;
    eth_device = interface;
    udp_payload_s = pktsize;
    tx_speed_bps = txrate;
    repeat_max = packets;
    rotate_svlan_prio = (int) svidrotate;
    host_dst = ipdst;
    host_src = ipsrc;

	//=====================================================================
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
			udp_checksum, udp_payload, udp_payload_s, lnet, 0);
	if (udp_ptag == -1) {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(lnet));
		goto bad;
	}

	//=====================================================================
	printf("libnet_build_ipv4\n");
	u_int16_t ip_hdr_len = LIBNET_IPV4_H + udp_pkt_len;

	if ((ip_dst = libnet_name2addr4(lnet, host_dst, LIBNET_DONT_RESOLVE))
			== -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		exit(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, host_src, LIBNET_DONT_RESOLVE))
			== -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		exit(EXIT_FAILURE);
	}

	ip_ptag = libnet_build_ipv4(ip_hdr_len, ip_tos, ip_id, ip_frag, ip_ttl,
			ip_proto, ip_chksum, ip_src, ip_dst, ip_payload, ip_payload_s, lnet,
			0);
	if (ip_ptag == -1) {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(lnet));
		goto bad;
	}

	//====================================================================
	printf("libnet_build_802_1q\n");
	svlan_ptag = libnet_build_802_1q(mac_dst, mac_src, stpid_val, svlan_prio,
			svlan_cfi_flag, svlan_id, ETHERTYPE_IP, svlan_payload, svlan_payload_s,
			lnet, 0);
	if (svlan_ptag == -1) {
		fprintf(stderr, "Can't build 802.1q header: %s\n",
				libnet_geterror(lnet));
		goto bad;
	}

	//=====================================================================
	/*
	 *  Write it to the wire.
	 */
	u_int32_t pkt_size = libnet_getpacket_size(lnet);
	printf("libnet_write, packet_size=%d\n", pkt_size);
	u_int16_t udp_prio_src_prt = udp_src_prt;
	u_int16_t udp_prio_dst_prt = udp_dst_prt;
	gettimeofday(&start_time, NULL);

	float rate_tx = ((((float)pkt_size * 8)/(float)tx_speed_bps))*1000000;
	printf("rate_tx=%f, pkt_size=%d, tx_speed_bps=%d\n", rate_tx, (pkt_size * 8), tx_speed_bps);
	printf("rate_tx=%d\n", (u_int32_t)rate_tx);

	for (repeat = 0; repeat < repeat_max; ++repeat) {
		int32_t bytes_written = libnet_write(lnet);
		if (bytes_written == -1) {
			fprintf(stderr, "Write error: %s\n", libnet_geterror(lnet));
			goto bad;
		}

		if (rotate_svlan_prio==1) {
			// modify packet
			if (svlan_prio == 7) {
				svlan_prio = 0;
				udp_prio_src_prt = udp_src_prt + svlan_prio;
				udp_prio_dst_prt = udp_dst_prt + svlan_prio;
			} else {
				svlan_prio++;
				udp_prio_src_prt++;
				udp_prio_dst_prt++;
			}
		}

		udp_ptag = libnet_build_udp(udp_prio_src_prt, udp_prio_dst_prt,
				udp_pkt_len, udp_checksum, udp_payload, udp_payload_s, lnet,
				udp_ptag);

		svlan_ptag = libnet_build_802_1q(mac_dst, mac_src, ETHERTYPE_VLAN,
				svlan_prio, svlan_cfi_flag, svlan_id, ETHERTYPE_IP, svlan_payload,
				svlan_payload_s, lnet, svlan_ptag);



		usleep(((u_int32_t)rate_tx - loop_delay));
	}

	gettimeofday(&end_time, NULL);

	libnet_timersub(&end_time, &start_time, &delta_time);
	fprintf(stdout, "Total time spent in loop: %ld.%ld\n", delta_time.tv_sec,
			delta_time.tv_usec);

	struct libnet_stats ls;
	libnet_stats(lnet, &ls);
	fprintf(stdout, "Packets sent:  %lld\n"
			"Packet errors: %lld\n"
			"Bytes written: %lld\n", ls.packets_sent, ls.packet_errors,
			ls.bytes_written);

	float delta_time_us = delta_time.tv_sec + (delta_time.tv_usec /1000000.0);
	float tx_speed = ((ls.bytes_written * 8) / delta_time_us);
	fprintf(stdout, "Tx speed :  %f bps\n", tx_speed);

	libnet_destroy(lnet);
	return (EXIT_SUCCESS);

	bad: {
		libnet_destroy(lnet);
		return (EXIT_FAILURE);
	}

}
