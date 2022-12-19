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


struct vlan_options
{
	GString*  macsrc;
	GString*  macdst;
	gint      id;
	gint      prio;
};
typedef struct vlan_options vlan_options_t;

struct ipv4_options
{
	GString*  dst;
	GString*  src;
	gint      dscp;
};
typedef struct ipv4_options ipv4_options_t;

struct udp_options
{
	gboolean  use;
	gint      src;
	gint      dst;
};
typedef struct udp_options udp_options_t;

struct arp_options
{
	gboolean  use;
};
typedef struct arp_options arp_options_t;

struct igmp_options
{
	gboolean  use;
	gboolean  type_query;
	gboolean  type_reportv1;
	gboolean  type_reportv2;
	gboolean  type_unknown;
	gboolean  type_leave;
	GString*  grp;
};
typedef struct igmp_options igmp_options_t;

struct igmp_query_msg
{
	guint8 QRV : 3;
	guint8 suppress_router_side_processing : 1;
	guint8 reserved : 4;
	guint16 QQIC : 8;
	guint16 num_of_sources : 8;
	guint32* sources;
};
typedef struct igmp_query_msg igmp_query_msg_t;


struct tx_options
{
	GString*  interface;
	gboolean  rotate;
	gint      pktsize;
	gint      rate;
	gint      packets;
};
typedef struct tx_options tx_options_t;

struct parsed_options
{
	tx_options_t   tx;
	vlan_options_t vlan;
	ipv4_options_t ipv4;
	arp_options_t  arp;
	igmp_options_t igmp;
	udp_options_t  udp;
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

gint32 buildQueuePacketArp(guint8 queue, libnet_t *lnet, parsed_options_t* options);

gint32 buildQueuePacketIgmp(guint8 queue, libnet_t *lnet, parsed_options_t* options);
/*
 ============================================================================
 */
gint32 main(int argc, char *argv[]) {

	printf("=====  started ======\n");

	parsed_options_t options;
	options.tx.interface =  g_string_new("eth0");
	options.tx.pktsize   =  0;
	options.tx.rate      =  0;
	options.tx.packets   =  0;
	options.tx.rotate    =  0;

	options.vlan.macsrc  = g_string_new("00:00:00:00:00:00");
	options.vlan.macdst  = g_string_new("00:00:00:00:00:00");
	options.vlan.id      =  0;
	options.vlan.prio    = -1;

	options.ipv4.dst     = g_string_new("000.000.000.000");
	options.ipv4.src     = g_string_new("000.000.000.000");
	options.ipv4.dscp    = 0;

	options.arp.use      =  FALSE;

	options.igmp.use            =  FALSE;
	options.igmp.type_query     =  FALSE;
	options.igmp.type_reportv1  =  FALSE;
	options.igmp.type_reportv2  =  FALSE;
	options.igmp.type_unknown   =  FALSE;
	options.igmp.type_leave     =  FALSE;
	options.igmp.grp            =  g_string_new("000.000.000.000");;

	options.udp.use      =  TRUE;
	options.udp.src      =  0;
	options.udp.dst      =  0;

	//==========================================================================
	parseOptions(argc,argv,&options);

	//==========================================================================
	printf("init libnet\n");
	gint q = 0;
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *udp_queue[QUEUE_SIZE];
	libnet_t *arp_queue[QUEUE_SIZE];
	libnet_t *igmp_queue[QUEUE_SIZE];

	for (q = QUEUE_0; q < QUEUE_SIZE; q++) {
		//==========================================================================
		udp_queue[q] = libnet_init(LIBNET_LINK, options.tx.interface->str,errbuf);
		if (udp_queue[q] == NULL ) {
			fprintf(stderr, "libnet_init() failed: %s", errbuf);
			goto bad;
		}
		if (buildQueuePacketUdp(q, udp_queue[q], &options) == EXIT_FAILURE)
			goto bad;
		//==========================================================================
		arp_queue[q] = libnet_init(LIBNET_LINK, options.tx.interface->str, errbuf);
		if (arp_queue[q] == NULL ) {
			fprintf(stderr, "libnet_init() failed: %s", errbuf);
			goto bad;
		}
		if (buildQueuePacketArp(q, arp_queue[q], &options) == EXIT_FAILURE )
			goto bad;
		//==========================================================================
		igmp_queue[q] = libnet_init(LIBNET_LINK, options.tx.interface->str, errbuf);
		if (igmp_queue[q] == NULL ) {
			fprintf(stderr, "libnet_init() failed: %s", errbuf);
			goto bad;
		}
		if (buildQueuePacketIgmp(q, igmp_queue[q], &options) == EXIT_FAILURE )
			goto bad;
	}


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
    tx_speed_bps = options.tx.rate;
    repeat_max = options.tx.packets;
    rotate_vlan_prio = (int) options.tx.rotate;
	u_int8_t queue_prio = QUEUE_0;

	libnet_t * tx_queue;
	if (options.udp.use)  tx_queue = udp_queue[queue_prio];
	if (options.arp.use)  tx_queue = arp_queue[queue_prio];
	if (options.igmp.use) tx_queue = igmp_queue[queue_prio];

	u_int32_t pkt_size = libnet_getpacket_size(&tx_queue[queue_prio]);
	printf("libnet_write, packet_size=%d\n", pkt_size);
	gettimeofday(&start_time, NULL);
	float rate_tx = ((((float)pkt_size * 8)/(float)tx_speed_bps))*1000000;
	printf("rate_tx=%f, pkt_size=%d (bits), tx_speed=%d (bits/s)\n", rate_tx, (pkt_size * 8), tx_speed_bps);
	printf("rate_tx=%d\n", (u_int32_t)rate_tx);

	for (repeat = 0; repeat < repeat_max; ++repeat) {
		int32_t bytes_written = libnet_write(&tx_queue[queue_prio]);
		if (bytes_written == -1) {
			fprintf(stderr, "Write error: %s\n", libnet_geterror(&tx_queue[queue_prio]));
			goto bad;
		}

		if (rotate_vlan_prio==1) {
			// modify packet
			if (queue_prio == QUEUE_7) {
				queue_prio = QUEUE_0;
			} else {
				queue_prio++;
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

		libnet_stats(&tx_queue[queue_stat], &ls[queue_stat]);
		fprintf(stdout, "udp_queue[%d]: Packets sent:  %llu,"
				"Packet errors: %llu,"
				"Bytes written: %llu\n",queue_stat,
				(long long unsigned int)ls[queue_stat].packets_sent,
				(long long unsigned int)ls[queue_stat].packet_errors,
				(long long unsigned int)ls[queue_stat].bytes_written);

		float delta_time_us = delta_time.tv_sec + (delta_time.tv_usec /1000000.0);
		float tx_speed = ((ls[queue_stat].bytes_written * 8) / delta_time_us);
		fprintf(stdout, "udp_queue[%d]: Tx speed :  %f bps\n", queue_stat, tx_speed);

	}


	for ( q = QUEUE_0; q<QUEUE_SIZE; q++) {
		libnet_destroy(udp_queue[q]);
		libnet_destroy(arp_queue[q]);
		libnet_destroy(igmp_queue[q]);
	}
	return (EXIT_SUCCESS);

	bad: {
		for ( q = QUEUE_0; q<QUEUE_SIZE; q++) {
			libnet_destroy(udp_queue[q]);
			libnet_destroy(arp_queue[q]);
			libnet_destroy(igmp_queue[q]);
		}
		return (EXIT_FAILURE);
	}

}

gint32 parseOptions(int argc, char *argv[], parsed_options_t* options)
{

	// g_print("====> Entering   %s:%d\n",__FUNCTION__,__LINE__) ;

	GOptionEntry cmd_entries[] = {
		{ "interface"  , 'i', 0                      , G_OPTION_ARG_STRING , &((options->tx.interface)->str)  , "tx interface", NULL },
		{ "pktsize"    , 's', 0                      , G_OPTION_ARG_INT    , &(options->tx.pktsize )          , "tx payload size in bytes", NULL },
		{ "txrate"     , 't', 0                      , G_OPTION_ARG_INT    , &(options->tx.rate  )            , "tx rate in bps", NULL },
		{ "packets"    , 'p', 0                      , G_OPTION_ARG_INT    , &(options->tx.packets )          , "tx number of packets ", NULL },
		{ "rotate"     ,  0 , 0                      , G_OPTION_ARG_NONE   , &(options->tx.rotate)            , "tx rotate queue", NULL },
		{ "macsrc"     ,  0 , 0                      , G_OPTION_ARG_STRING , &((options->vlan.macsrc)->str)   , "vlan source mac address", NULL },
		{ "macdst"     ,  0 , 0                      , G_OPTION_ARG_STRING , &((options->vlan.macdst)->str)   , "vlan destination mac address", NULL },
		{ "vid"        ,  0 , 0                      , G_OPTION_ARG_INT    , &(options->vlan.id)              , "vlan id [1-4096]", NULL },
		{ "vidprio"    ,  0 , 0                      , G_OPTION_ARG_INT    , &(options->vlan.prio)            , "vlan priority [0-7]", NULL },
		{ "ipsrc"      ,  0 , 0                      , G_OPTION_ARG_STRING , &((options->ipv4.src)->str)      , "ipv4 source address ", NULL },
		{ "ipdst"      ,  0 , 0                      , G_OPTION_ARG_STRING , &((options->ipv4.dst)->str)      , "ipv4 dest address ", NULL },
		{ "dscp"       ,  0 , 0                      , G_OPTION_ARG_INT    , &(options->ipv4.dscp)            , "ipv4 dscp [0-63]", NULL },
		{ "arp"        ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->arp.use)         , "send arp traffic", NULL },
		{ "igmp"       ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.use)        , "send igmp traffic", NULL },
		{ "igmpreportv1", 0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.type_reportv1 ) , "send igmp report v1", NULL },
		{ "igmpreportv2", 0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.type_reportv2 ) , "send igmp report v2", NULL },
		{ "igmpquery"  ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.type_query )    , "send igmp query", NULL },
		{ "igmpleave"  ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.type_leave )    , "send igmp leave", NULL },
		{ "igmpunknown",  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->igmp.type_unknown )    , "send igmp unknown type", NULL },
		{ "igmpgrp"    ,  0 , 0                      , G_OPTION_ARG_STRING , &((options->igmp.grp)->str)         , "ipv4 group address ", NULL },
		{ "udp"        ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_NONE  , &(options->udp.use  )           , "send udp traffic", NULL },
		{ "udpsrc"     ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_INT   , &(options->udp.src  )           , "udp source port", NULL },
		{ "udpdst"     ,  0 , G_OPTION_FLAG_OPTIONAL_ARG  , G_OPTION_ARG_INT   , &(options->udp.dst  )           , "udp dest port", NULL },
		{ NULL }
	};

	GError *error = NULL;
	GOptionContext *context;

        // g_print("====> %s:%d g_option_context_new\n", __FUNCTION__, __LINE__);
        context = g_option_context_new("vlan priority traffic generator");
        // g_print("====> %s:%d g_option_context_add_main_entries\n", __FUNCTION__, __LINE__);
        g_option_context_add_main_entries(context, cmd_entries, NULL);
        // g_print("====> %s:%d g_option_context_parse\n", __FUNCTION__, __LINE__);
        if (!g_option_context_parse(context, &argc, &argv, &error)) {
          // g_print("option parsing failed: %s\n", error->message);
          exit(EXIT_FAILURE);
        }

        // checks
	if (options->vlan.id < 1 || options->vlan.id > 4096) {
		fprintf(stderr, "invalid vid: %d\n", options->vlan.id);
		// g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
		return (EXIT_FAILURE);
	}

	if (options->vlan.prio < 0 || options->vlan.prio > 7) {
		fprintf(stderr, "invalid vlan priority: %d\n", options->vlan.prio);
		// g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
		return (EXIT_FAILURE);
	}

	if (options->ipv4.dscp < 0 || options->ipv4.dscp > 63) {
		fprintf(stderr, "invalid dscp: %d\n", options->ipv4.dscp);
		// g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
		return (EXIT_FAILURE);
	}


	// g_print("tx interface %s\n",(options->tx.interface)->str ) ;
	// g_print("tx rotate    %d\n",options->tx.rotate           ) ;
	// g_print("tx pktsize   %d\n",options->tx.pktsize          ) ;
	// g_print("tx rate      %d\n",options->tx.rate             ) ;
    // g_print("tx packets   %d\n",options->tx.packets          ) ;
	// g_print("vlan macdst  %s\n",(options->vlan.macdst)->str  ) ;
	// g_print("vlan macsrc  %s\n",(options->vlan.macsrc)->str  ) ;
	// g_print("vlan vid     %d\n",options->vlan.id             ) ;
	// g_print("vlan prio    %d\n",options->vlan.prio           ) ;
	// g_print("ipv4 ipdst   %s\n",(options->ipv4.dst)->str     ) ;
	// g_print("ipv4 ipsrc   %s\n",(options->ipv4.src)->str     ) ;
	// g_print("ipv4 dscp    %d\n",options->ipv4.dscp           ) ;
	// g_print("udp          %d\n",options->udp.use             ) ;
	// g_print("udp dst      %d\n",options->udp.dst             ) ;
	// g_print("udp src      %d\n",options->udp.src             ) ;
	// g_print("igmp           %d\n",options->igmp.use            ) ;
	// g_print("igmp leave     %d\n",options->igmp.type_leave     ) ;
	// g_print("igmp query     %d\n",options->igmp.type_query     ) ;
	// g_print("igmp report v1 %d\n",options->igmp.type_reportv1  ) ;
	// g_print("igmp report v2 %d\n",options->igmp.type_reportv2  ) ;
	// g_print("igmp unknown %d\n",options->igmp.type_unknown  ) ;
	// g_print("igmp group   %s\n",(options->igmp.grp)->str     ) ;

	// g_print("====> Exiting   %s:%d\n",__FUNCTION__,__LINE__) ;
	return (EXIT_SUCCESS);
}

gint32 buildQueuePacketUdp(guint8 queue, libnet_t *lnet, parsed_options_t* options)
{
	//==========================================================================
	int len;

	//=====================================================================
	printf("libnet_build_udp\n");
	libnet_ptag_t udp_ptag = 0;
	u_int16_t udp_checksum = 0;
	u_int8_t *udp_payload; // ==> user payload
	int j = 0;
	u_char payload[options->tx.pktsize];
	for (j = 0; j < options->tx.pktsize; j++) {
		payload[j] = libnet_get_prand(LIBNET_PR8);
	}
	udp_payload = &payload[0];

	u_int32_t udp_pkt_len = LIBNET_UDP_H + options->tx.pktsize;
	udp_ptag = libnet_build_udp(
			((u_int16_t) options->udp.src + queue),
			((u_int16_t) options->udp.dst + queue),
			udp_pkt_len, udp_checksum, udp_payload,
			options->tx.pktsize, lnet, 0);
	if (udp_ptag == -1) {
		fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}

	//=====================================================================
	printf("libnet_build_ipv4\n");
	libnet_ptag_t ip_ptag = 0;
	u_int8_t ip_id = 0;
	u_int8_t ip_frag = 0;
	u_int8_t ip_ttl = 64;
	u_short ip_proto = IPPROTO_UDP;
	u_int16_t ip_chksum = 0;
	u_int8_t *ip_payload = NULL;
	u_int32_t ip_payload_s = 0;
	u_int16_t ip_hdr_len = LIBNET_IPV4_H + udp_pkt_len;

	u_int8_t  ip_tos    = ((u_int8_t) options->ipv4.dscp + queue) << 2;
	u_int32_t ip_src;
	u_int32_t ip_dst;
	if ((ip_dst = libnet_name2addr4(lnet, (options->ipv4.dst)->str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, (options->ipv4.src)->str, LIBNET_DONT_RESOLVE)) == -1) {
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

	u_char *mac_dst, *mac_src;
	mac_src = libnet_hex_aton((options->vlan.macsrc)->str, &len);
	u_int8_t new_byte = (mac_src[5]+queue);
	mac_src[5] = (u_char)new_byte;
	printf("mac_src[%X:%X:%X:%X:%X:%X] queue=%X new_byte=%X\n",
			mac_src[0],mac_src[1],mac_src[2],mac_src[3],mac_src[4],mac_src[5],queue,new_byte);
	mac_dst = libnet_hex_aton((options->vlan.macdst)->str, &len);
	if (options->vlan.id != 0) {
		//====================================================================
		printf("libnet_build_802_1q\n");
		// layer 2
		libnet_ptag_t vlan_ptag = 0;
		u_int8_t vlan_cfi_flag = 0;
		u_int8_t *vlan_payload = NULL;
		u_int32_t vlan_payload_s = 0;
		u_int8_t vlan_prio;
		u_int16_t vlan_id;

		vlan_id = (u_int16_t) options->vlan.id;
		vlan_prio = (u_int8_t) options->vlan.prio + queue;

		vlan_ptag = libnet_build_802_1q(mac_dst, mac_src, ETHERTYPE_VLAN, vlan_prio,
				vlan_cfi_flag, vlan_id, ETHERTYPE_IP, vlan_payload, vlan_payload_s,
				lnet, 0);
		if (vlan_ptag == -1) {
			fprintf(stderr, "Can't build 802.1q header: %s\n",
					libnet_geterror(lnet));
			return(EXIT_FAILURE);
		}
	} else {
		libnet_ptag_t ether_tag = 0;
		u_int8_t *ether_payload = NULL;
		u_int32_t ether_payload_s = 0;
		ether_tag = libnet_build_ethernet(mac_dst, mac_src, ETHERTYPE_IP, ether_payload, ether_payload_s, lnet, 0);
		if (ether_tag == -1) {
			fprintf(stderr, "Can't build ethernet header: %s\n",
					libnet_geterror(lnet));
			return(EXIT_FAILURE);
		}
	}
	return (EXIT_SUCCESS);

}

gint32 buildQueuePacketArp(guint8 queue, libnet_t *lnet, parsed_options_t* options)
{
	//==========================================================================
	int len;
	u_char *mac_dst, *mac_src;
    mac_src = libnet_hex_aton((options->vlan.macsrc)->str, &len);
    u_int8_t new_byte = (mac_src[5]+queue);
    mac_src[5] = (u_char)new_byte;
    mac_dst = libnet_hex_aton((options->vlan.macdst)->str, &len);


	//==========================================================================
	// layer 2
	printf("libnet_build_ARP\n");
	u_int32_t ip_src;
	u_int32_t ip_dst;
	if ((ip_dst = libnet_name2addr4(lnet, (options->ipv4.dst)->str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, (options->ipv4.src)->str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}

	libnet_ptag_t arp_ptag = 0;
	arp_ptag = libnet_build_arp(
            ARPHRD_ETHER,                           /* hardware addr */
            ETHERTYPE_IP,                           /* protocol addr */
            6,                                      /* hardware addr size */
            4,                                      /* protocol addr size */
            ARPOP_REPLY,                            /* operation type */
            mac_src,                               /* sender hardware addr */
            (u_int8_t *)&ip_src,                         /* sender protocol addr */
            mac_dst,                               /* target hardware addr */
            (u_int8_t *)&ip_dst,                         /* target protocol addr */
            NULL,                                   /* payload */
            0,                                      /* payload size */
            lnet,                                      /* libnet context */
            0);                                     /* libnet id */
	if (arp_ptag == -1) {
		fprintf(stderr, "Can't build ARP header: %s\n",
				libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}

	//====================================================================
	// layer 2
	printf("libnet_build_802_1q\n");

	libnet_ptag_t vlan_ptag = 0;
	u_int8_t vlan_cfi_flag = 0;
	u_int8_t *vlan_payload = NULL;
	u_int32_t vlan_payload_s = 0;
	u_int8_t vlan_prio;
	u_int16_t vlan_id;

    vlan_id = (u_int16_t) options->vlan.id;
    vlan_prio = (u_int8_t) options->vlan.prio + queue;

	vlan_ptag = libnet_build_802_1q(mac_dst, mac_src, ETHERTYPE_VLAN, vlan_prio,
			vlan_cfi_flag, vlan_id, ETHERTYPE_ARP, vlan_payload, vlan_payload_s,
			lnet, 0);
	if (vlan_ptag == -1) {
		fprintf(stderr, "Can't build 802.1q header: %s\n",
				libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}

	return (EXIT_SUCCESS);
}

gint32 buildQueuePacketIgmp(guint8 queue, libnet_t *lnet, parsed_options_t* options)
{
	//==========================================================================
	int len;
	u_char *mac_dst, *mac_src;
    mac_src = libnet_hex_aton((options->vlan.macsrc)->str, &len);
    u_int8_t new_byte = (mac_src[5]+queue);
    mac_src[5] = (u_char)new_byte;
    mac_dst = libnet_hex_aton((options->vlan.macdst)->str, &len);


	//==========================================================================
	// layer 3
	printf("libnet_build_IGMP %s \n",(options->igmp.grp)->str);
	u_int32_t igmp_grp;
	if ((igmp_grp = libnet_name2addr4(lnet, (options->igmp.grp)->str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad igmp grp address: %s\n", optarg);
		return(EXIT_FAILURE);
	}
	uint8_t igmp_type = 0;
	uint8_t igmp_reserved = 0;
	printf("libnet_build_IGMP\n");

	if (options->igmp.use == FALSE) {
		return (EXIT_SUCCESS);
	}

	igmp_query_msg_t igmp_query_hdr;
	memset(&igmp_query_hdr,0,sizeof(igmp_query_hdr));
	u_int8_t *igmp_payload; // ==> user payload
	guint16 payload_size = 0;

	if (options->igmp.type_leave) {
		igmp_type = IGMP_LEAVE_GROUP;
	} else if (options->igmp.type_query) {
		uint8_t igmp_query_max_reserved_time = 1;
		igmp_reserved = igmp_query_max_reserved_time;
		igmp_type = IGMP_MEMBERSHIP_QUERY;
		igmp_query_hdr.QRV = 1;
		igmp_query_hdr.suppress_router_side_processing = 0;
		igmp_query_hdr.reserved = 0;
		igmp_query_hdr.QQIC = 20;
		igmp_query_hdr.num_of_sources = 0;
		igmp_payload = (u_int8_t*) &igmp_query_hdr;
		payload_size = sizeof(igmp_query_hdr);
	} else if (options->igmp.type_reportv1) {
		igmp_type = IGMP_V1_MEMBERSHIP_REPORT;
	} else if (options->igmp.type_reportv2) {
		igmp_type = IGMP_V2_MEMBERSHIP_REPORT;
	} else if (options->igmp.type_unknown) {
		igmp_type = 0x99;
	} else {
		fprintf(stderr, "invalid igmp msg type");
		return(EXIT_FAILURE);
	}


	libnet_ptag_t igmp_ptag = 0;
	u_int16_t igmp_pkt_len = LIBNET_IGMP_H + payload_size;
	u_int16_t igmp_chksum = 0;

	igmp_ptag = libnet_build_igmp(igmp_type,
								  igmp_reserved,
								  igmp_chksum,
								  igmp_grp,
								  igmp_payload,
								  payload_size,
								  lnet,
								  0);
	if (igmp_ptag == -1) {
		fprintf(stderr, "Can't build IGMP header: %s\n", libnet_geterror(lnet));
		return(EXIT_FAILURE);
	}
	printf("finished libnet_build_IGMP\n");
	//=====================================================================
	printf("libnet_build_ipv4\n");
	libnet_ptag_t ip_ptag = 0;
	u_int8_t ip_id = 0;
	u_int8_t ip_frag = 0;
	u_int8_t ip_ttl = 1;
	u_short ip_proto = IPPROTO_IGMP;
	u_int16_t ip_chksum = 0;
	u_int8_t *ip_payload = NULL;
	u_int32_t ip_payload_s = 0;
	u_int16_t ip_hdr_len = LIBNET_IPV4_H + igmp_pkt_len;

	u_int32_t ip_dst;
	u_int32_t ip_src;
	u_int8_t  ip_tos    = ((u_int8_t) options->ipv4.dscp + queue) << 2;
	if ((ip_dst = libnet_name2addr4(lnet, (options->ipv4.dst)->str, LIBNET_DONT_RESOLVE)) == -1) {
		fprintf(stderr, "Bad source IP address: %s\n", optarg);
		return(EXIT_FAILURE);
	}
	if ((ip_src = libnet_name2addr4(lnet, (options->ipv4.src)->str, LIBNET_DONT_RESOLVE)) == -1) {
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
	// layer 2
	printf("libnet_build_802_1q\n");

	libnet_ptag_t vlan_ptag = 0;
	u_int8_t vlan_cfi_flag = 0;
	u_int8_t *vlan_payload = NULL;
	u_int32_t vlan_payload_s = 0;
	u_int8_t vlan_prio;
	u_int16_t vlan_id;

    vlan_id = (u_int16_t) options->vlan.id;
    vlan_prio = (u_int8_t) options->vlan.prio + queue;

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
