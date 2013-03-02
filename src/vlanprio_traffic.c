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


struct parsed_options
{
	GString*  interface;
	GString*  macsrc;
	GString*  macdst;
	GString*  ipdst;
	GString*  ipsrc;
	gint      vid;
	gint      vidprio;
	gboolean  vidrotate;
	gint      udpsrc;
	gint      udpdst;
	gint      pktsize;
	gint      txrate;
	gint      packets;
};
typedef struct parsed_options parsed_options_t;

enum {
   QUEUE_0 = 0,
   QUEUE_1 = 1,
   QUEUE_2 = 2,
   QUEUE_3 = 3,
   QUEUE_4 = 4,
   QUEUE_5 = 5,
   QUEUE_6 = 6,
   QUEUE_7 = 7,
   QUEUE_SIZE = 8,
}  QUEUE;



gint32 parseOptions(int argc, char *argv[], parsed_options_t* options);

gint32 buildQueuePacketUdp(guint8 queue, libnet_t *lnet, parsed_options_t* options);

/*
 ============================================================================
 */
gint32 main(int argc, char *argv[]) {

	printf("=====  started ======\n");

	parsed_options_t options;
	options.interface = g_string_new("eth0");
	options.macsrc    = g_string_new("00:00:00:00:00:00");
	options.macdst    = g_string_new("00:00:00:00:00:00");
	options.ipdst     = g_string_new("000.000.000.000");
	options.ipsrc     = g_string_new("000.000.000.000");
	options.vid       =  0;
	options.vidprio   = -1;
	options.vidrotate =  0;
	options.udpsrc    =  0;
	options.udpdst    =  0;
	options.pktsize   =  0;
	options.txrate    =  0;
	options.packets   =  0;

	//==========================================================================
	parseOptions(argc,argv,&options);

	printf("init libnet\n");
	gint q = 0;
	libnet_t *tx_queue[QUEUE_SIZE];
	for ( q = QUEUE_0; q<QUEUE_SIZE; q++) {
		char errbuf[LIBNET_ERRBUF_SIZE];
		tx_queue[q] = libnet_init(LIBNET_LINK, options.interface->str, errbuf);
		if (tx_queue[q] == NULL) {
			fprintf(stderr, "libnet_init() failed: %s", errbuf);
			goto bad;
		}
	}

	printf("build packet\n");
	if (buildQueuePacketUdp(QUEUE_0, tx_queue[QUEUE_0], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_1, tx_queue[QUEUE_1], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_2, tx_queue[QUEUE_2], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_3, tx_queue[QUEUE_3], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_4, tx_queue[QUEUE_4], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_5, tx_queue[QUEUE_5], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_6, tx_queue[QUEUE_6], &options) == EXIT_FAILURE) goto bad;
	if (buildQueuePacketUdp(QUEUE_7, tx_queue[QUEUE_7], &options) == EXIT_FAILURE) goto bad;


	//=====================================================================
	/*
	 *  Write it to the wire.
	 */
	int tx_speed_bps;
	struct timeval delta_time;
	struct timeval start_time;
	struct timeval end_time;
	int repeat = 0;
	int repeat_max = 0;
	int rotate_vlan_prio = 0;
	u_int32_t loop_delay = 65;
    tx_speed_bps = options.txrate;
    repeat_max = options.packets;
    rotate_vlan_prio = (int) options.vidrotate;
	u_int8_t tx_queue_prio = QUEUE_0;

	u_int32_t pkt_size = libnet_getpacket_size(tx_queue[tx_queue_prio]);
	printf("libnet_write, packet_size=%d\n", pkt_size);
	gettimeofday(&start_time, NULL);
	float rate_tx = ((((float)pkt_size * 8)/(float)tx_speed_bps))*1000000;
	printf("rate_tx=%f, pkt_size=%d, tx_speed_bps=%d\n", rate_tx, (pkt_size * 8), tx_speed_bps);
	printf("rate_tx=%d\n", (u_int32_t)rate_tx);

	for (repeat = 0; repeat < repeat_max; ++repeat) {
		int32_t bytes_written = libnet_write(tx_queue[tx_queue_prio]);
		if (bytes_written == -1) {
			fprintf(stderr, "Write error: %s\n", libnet_geterror(tx_queue[tx_queue_prio]));
			goto bad;
		}

		if (rotate_vlan_prio==1) {
			// modify packet
			if (tx_queue_prio == QUEUE_7) {
				tx_queue_prio = QUEUE_0;
			} else {
				tx_queue_prio++;
			}
		}

		usleep(((u_int32_t)rate_tx - loop_delay));
	}

	gettimeofday(&end_time, NULL);

	libnet_timersub(&end_time, &start_time, &delta_time);
	fprintf(stdout, "Total time spent in loop: %ld.%ld\n", delta_time.tv_sec,
			delta_time.tv_usec);

	guint queue_stat=0;
	struct libnet_stats ls[QUEUE_SIZE];
	for (queue_stat = QUEUE_0; queue_stat <= QUEUE_7; queue_stat++) {

		libnet_stats(tx_queue[queue_stat], &ls[queue_stat]);
		fprintf(stdout, "tx_queue[%d]: Packets sent:  %llu,"
				"Packet errors: %llu,"
				"Bytes written: %llu\n",queue_stat,
				(long long unsigned int)ls[queue_stat].packets_sent,
				(long long unsigned int)ls[queue_stat].packet_errors,
				(long long unsigned int)ls[queue_stat].bytes_written);

		float delta_time_us = delta_time.tv_sec + (delta_time.tv_usec /1000000.0);
		float tx_speed = ((ls[queue_stat].bytes_written * 8) / delta_time_us);
		fprintf(stdout, "tx_queue[%d]: Tx speed :  %f bps\n", queue_stat, tx_speed);

	}


	libnet_destroy(tx_queue[QUEUE_0]);
	libnet_destroy(tx_queue[QUEUE_1]);
	libnet_destroy(tx_queue[QUEUE_2]);
	libnet_destroy(tx_queue[QUEUE_3]);
	libnet_destroy(tx_queue[QUEUE_4]);
	libnet_destroy(tx_queue[QUEUE_5]);
	libnet_destroy(tx_queue[QUEUE_6]);
	libnet_destroy(tx_queue[QUEUE_7]);
	return (EXIT_SUCCESS);

	bad: {
		libnet_destroy(tx_queue[QUEUE_0]);
		libnet_destroy(tx_queue[QUEUE_1]);
		libnet_destroy(tx_queue[QUEUE_2]);
		libnet_destroy(tx_queue[QUEUE_3]);
		libnet_destroy(tx_queue[QUEUE_4]);
		libnet_destroy(tx_queue[QUEUE_5]);
		libnet_destroy(tx_queue[QUEUE_6]);
		libnet_destroy(tx_queue[QUEUE_7]);
		return (EXIT_FAILURE);
	}

}

gint32 parseOptions(int argc, char *argv[], parsed_options_t* options)
{

	g_print("====> Entering   %s:%d\n",__FUNCTION__,__LINE__) ;

	GOptionEntry cmd_entries[] = {
		{ "interface"  , 'i', 0, G_OPTION_ARG_STRING , &((options->interface)->str)  , "interface", NULL },
		{ "macsrc"     ,  0 , 0, G_OPTION_ARG_STRING , &((options->macsrc)->str)     , "source mac address", NULL },
		{ "macdst"     ,  0 , 0, G_OPTION_ARG_STRING , &((options->macdst)->str)     , "destination mac address", NULL },
		{ "ipsrc"      ,  0 , 0, G_OPTION_ARG_STRING , &((options->ipsrc)->str)      , "source IP ", NULL },
		{ "ipdst"      ,  0 , 0, G_OPTION_ARG_STRING , &((options->ipdst)->str)      , "dest IP ", NULL },
		{ "vid"        ,  0 , 0, G_OPTION_ARG_INT    , &(options->vid)            , "vlan id [1-4096]", NULL },
		{ "vidprio"    ,  0 , 0, G_OPTION_ARG_INT    , &(options->vidprio)        , "vlan priority [0-7]", NULL },
		{ "rotate"     ,  0 , 0, G_OPTION_ARG_NONE   , &(options->vidrotate)      , "rotate vlan priority", NULL },
		{ "udpsrc"     ,  0 , 0, G_OPTION_ARG_INT    , &(options->udpsrc  )       , "source UDP port", NULL },
		{ "udpdst"     ,  0 , 0, G_OPTION_ARG_INT    , &(options->udpdst  )       , "dest UDP port", NULL },
		{ "pktsize"    , 's', 0, G_OPTION_ARG_INT    , &(options->pktsize )       , "UDP payload size in bytes", NULL },
		{ "txrate"     , 't', 0, G_OPTION_ARG_INT    , &(options->txrate  )       , "transmission rate in bps", NULL },
		{ "packets"    , 'p', 0, G_OPTION_ARG_INT    , &(options->packets )       , "number of packets for tx", NULL },
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
	if (options->vid < 1 || options->vid > 4096) {
		fprintf(stderr, "invalid vid: %d\n", options->vid);
		g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
		return (EXIT_FAILURE);
	}

	if (options->vidprio < 0 || options->vidprio > 7) {
		fprintf(stderr, "invalid vidprio: %d\n", options->vidprio);
		g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
		return (EXIT_FAILURE);
	}

	g_print("interface   %s\n",(options->interface)->str ) ;
	g_print("macdst      %s\n",(options->macdst)->str    ) ;
	g_print("ipdst       %s\n",(options->ipdst)->str     ) ;
	g_print("macsrc      %s\n",(options->macsrc)->str    ) ;
	g_print("ipsrc       %s\n",(options->ipsrc)->str     ) ;
	g_print("vid        %d\n" ,options->vid         ) ;
	g_print("vidprio    %d\n" ,options->vidprio     ) ;
	g_print("vidrotate  %d\n" ,options->vidrotate   ) ;
	g_print("udpdst      %d\n",options->udpdst      ) ;
	g_print("udpsrc      %d\n",options->udpsrc      ) ;
	g_print("pktsize     %d\n",options->pktsize     ) ;
	g_print("txrate      %d\n",options->txrate      ) ;
    g_print("packets     %d\n",options->packets     ) ;

	g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
	return (EXIT_SUCCESS);
}

gint32 buildQueuePacketUdp(guint8 queue, libnet_t *lnet, parsed_options_t* options)
{
	//==========================================================================
	int len;

	// layer 2
	u_char *mac_dst, *mac_src;
	libnet_ptag_t vlan_ptag = 0;
	u_int8_t vlan_cfi_flag = 0;
	u_int8_t *vlan_payload = NULL;
	u_int32_t vlan_payload_s = 0;
	u_int8_t vlan_prio;
	u_int16_t vlan_id;

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


    //eth_device = (options.interface)->str;
    mac_src = libnet_hex_aton((options->macsrc)->str, &len);
    mac_dst = libnet_hex_aton((options->macdst)->str, &len);
    vlan_id = (u_int16_t) options->vid;
    udp_payload_s = options->pktsize;

    vlan_prio = (u_int8_t) options->vidprio + queue;
    udp_src_prt = (u_int16_t) options->udpsrc + queue;
    udp_dst_prt = (u_int16_t) options->udpdst + queue;

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
		return(EXIT_FAILURE);
	}

	//=====================================================================
	printf("libnet_build_ipv4\n");
	u_int16_t ip_hdr_len = LIBNET_IPV4_H + udp_pkt_len;

	if ((ip_dst = libnet_name2addr4(lnet, (options->ipdst)->str, LIBNET_DONT_RESOLVE))
			== -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, (options->ipsrc)->str, LIBNET_DONT_RESOLVE))
			== -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}

	ip_ptag = libnet_build_ipv4(ip_hdr_len, ip_tos, ip_id, ip_frag, ip_ttl,
			ip_proto, ip_chksum, ip_src, ip_dst, ip_payload, ip_payload_s, lnet,
			0);
	if (ip_ptag == -1) {
		fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}

	//====================================================================
	printf("libnet_build_802_1q\n");
	vlan_ptag = libnet_build_802_1q(mac_dst, mac_src, ETHERTYPE_VLAN, vlan_prio,
			vlan_cfi_flag, vlan_id, ETHERTYPE_IP, vlan_payload, vlan_payload_s,
			lnet, 0);
	if (vlan_ptag == -1) {
		fprintf(stderr, "Can't build 802.1q header: %s\n",
				libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}
	return (EXIT_SUCCESS);

}
