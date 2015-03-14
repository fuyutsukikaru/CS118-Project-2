/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <assert.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /*sr_send_icmp(sr, packet, interface, DEST_HOST_UNREACHABLE_TYPE, DEST_HOST_UNREACHABLE_CODE);*/

  /* fill in code here */

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to load ethernet header, insufficient length\n");
    return;
  }

  uint16_t et = ethertype(packet);

  /* Handle IP protocol */
  if (et == ethertype_ip) {
    fprintf(stderr, "Received an IP packet!\n");
    minlength += sizeof(sr_ip_hdr_t);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t ipsum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0; /* checksum field is assumed to be 0 for calculation */
    uint32_t cks = cksum(ip_hdr, ip_hdr->ip_hl * sizeof(unsigned int));

    fprintf(stderr, "Target ip is\n");
    print_addr_ip_int(ntohl(ip_hdr->ip_dst));
    struct sr_if* dest_iface = sr_find_matching_interface(sr, ip_hdr->ip_dst);

    if (len < minlength) {
      fprintf(stderr, "Failed to load IP header, insufficient length\n");
      return;
    } else if (ipsum != cks) {
      fprintf(stderr, "Checksum mismatch\n");
      return;
    } else if (dest_iface) {
      fprintf(stderr, "IP packet is for us\n");

      /* double check these */
      if (ip_hdr->ip_p == ip_protocol_icmp) {
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if (icmp_hdr->icmp_type == ECHO_REQUEST_TYPE && icmp_hdr->icmp_code == ECHO_REQUEST_CODE) {
          fprintf(stderr, "Received an echo request, sending reply\n");
          sr_send_icmp(sr, packet, interface, ECHO_REPLY_TYPE, 0);
        }
      } else {
        sr_send_icmp(sr, packet, interface, PORT_UNREACHABLE_TYPE, PORT_UNREACHABLE_CODE);
      }

    } else {
      fprintf(stderr, "IP packet needs to be forwarded\n");
      print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

      if (ip_hdr->ip_ttl == 1) {
        /* time exceeded, send icmp */
        fprintf(stderr, "time exceeded\n");
        sr_send_icmp(sr, packet, interface, TIME_EXCEEDED_TYPE, TIME_EXCEEDED_CODE);
        return;
      }

      ip_hdr->ip_ttl--;
      ip_hdr->ip_sum = 0; /* checksum field is assumed to be 0 for calculation */
      ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * sizeof(unsigned int));

      printf("Routing Table is: ");
      sr_print_routing_table(sr);
      fprintf(stderr, "Trying to send packet to ");
      print_addr_ip_int(ntohl(ip_hdr->ip_dst));

      struct sr_rt* matching_entry = sr_longest_prefix_match(sr, ntohl(ip_hdr->ip_dst));

      if (!matching_entry) {
        fprintf(stderr, "Destination unreachable LPM FAILED\n");
        sr_send_icmp(sr, packet, interface, DEST_NET_UNREACHABLE_TYPE, DEST_NET_UNREACHABLE_CODE);
        return;
      }


      fprintf(stderr, "Now forwarding packet\n");
      sr_send_ip_packet(sr, packet, matching_entry->gw.s_addr, len, matching_entry->interface);
    }
  } else if (et == ethertype_arp) {
    fprintf(stderr, "Received an ARP packet!\n");

    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "Failed to load ARP header, insufficient length\n");
      return;
    } else {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        fprintf(stderr, "It was a request!\n");
        print_hdr_arp(arp_hdr);
        struct sr_if* iface = sr_find_matching_interface(sr, arp_hdr->ar_tip);
        sr_send_arp_reply(sr, arp_hdr, iface->name);
      } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        fprintf(stderr, "It was a reply!\n");
        print_hdr_arp(arp_hdr);
        struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (req) {
          fprintf(stderr, "Now handling packets waiting on reply\n");
          struct sr_packet* pkt = req->packets;
          struct sr_arpentry* entry;
          struct sr_if* iface = sr_get_interface(sr, interface);
          while (pkt) {
            entry = sr_arpcache_lookup(&sr->cache, req->ip);
            if (entry) {
              sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
              memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

              fprintf(stderr, "Sending waiting packet\n");
              print_hdr_eth(pkt->buf);
              print_hdr_ip((pkt->buf) + sizeof(sr_ethernet_hdr_t));
              sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
              pkt = pkt->next;
            } else {
              fprintf(stderr, "Queueing request\n");
              req = sr_arpcache_queuereq(&sr->cache, req->ip, pkt->buf, pkt->len, pkt->iface);
              handle_arpreq(sr, req);
            }

          }
          free(entry);
        }
        sr_arpreq_destroy(&sr->cache, req);
      }
    }
  } else {
    fprintf(stderr, "Unrecognized type: %d", et);
  }
}/* end sr_ForwardPacket */

struct sr_if* sr_find_matching_interface(struct sr_instance* sr, uint32_t ip) {
  struct sr_if* if_walker = 0;

  if_walker = sr->if_list;
  while(if_walker) {
    if (if_walker->ip == ip) {
      return if_walker;
    }
    if_walker = if_walker->next;
  }

  return 0;
}

void sr_send_ip_packet(struct sr_instance* sr, uint8_t* packet, uint32_t tip, uint32_t len, char* interface) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, tip);
  struct sr_if* iface = sr_get_interface(sr, interface);

  if (entry) {
    sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)packet;
    memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, interface);

    fprintf(stderr, "Sending an IP packet to ");
    print_addr_eth(entry->mac);

    free(entry);
  } else {
    fprintf(stderr, "Couldn't find entry, queueing arp\n");
    sr_arpcache_queuereq(&sr->cache, tip, packet, len, interface);
  }
}

void sr_send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, char* interface) {
  struct sr_if* iface = sr_get_interface(sr, interface);

  uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)packet;
  memcpy(ether_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ether_hdr->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* reply_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  reply_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  reply_arp_hdr->ar_pro = htons(ethertype_ip);
  reply_arp_hdr->ar_hln = 0x06; /* 6 bytes for ethernet */
  reply_arp_hdr->ar_pln = 0x04; /* 4 bytes for ip */
  reply_arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip = iface->ip;
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

  fprintf(stderr, "Sending arp reply!\n");
  print_hdr_arp((uint8_t *)reply_arp_hdr);
  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
  free(packet);
}

void sr_send_arp_request(struct sr_instance* sr, struct sr_arpreq* req) {
  fprintf(stderr, "Sending ARP request!\n");
  uint8_t* packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

  struct sr_rt* rte = sr_longest_prefix_match(sr, ntohl(req->ip));

  if (!rte) {
    fprintf(stderr, "Router cannot reach destination ip\n");
    print_addr_ip_int(req->ip);
    free(packet);
    return;
  }

  fprintf(stderr, "Matched interface: %s\n", rte->interface);

  struct sr_if* iface = sr_get_interface(sr, rte->interface);
  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)packet;

  /* arp requests are sent to broadcast mac address */
  memset(ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  ether_hdr->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* request_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  request_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  request_arp_hdr->ar_pro = htons(ethertype_ip);
  request_arp_hdr->ar_hln = 0x06; /* 6 bytes for ethernet */
  request_arp_hdr->ar_pln = 0x04; /* 4 bytes for ip */
  request_arp_hdr->ar_op = htons(arp_op_request);
  memcpy(request_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  request_arp_hdr->ar_sip = iface->ip;
  memset(request_arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  request_arp_hdr->ar_tip = req->ip;

  print_hdr_arp((uint8_t *)request_arp_hdr);
  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
  free(packet);
}

void sr_send_icmp(struct sr_instance* sr, uint8_t* packet, char* interface, uint8_t type, uint8_t code) {
  sr_ip_hdr_t* recv_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint8_t* icmp_packet = malloc(sizeof(sr_ethernet_hdr_t) + ntohs(recv_ip_hdr->ip_len));

  sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t*)icmp_packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt* match = sr_longest_prefix_match(sr, ntohl(recv_ip_hdr->ip_src));
  struct sr_if* iface = sr_get_interface(sr, match->interface);

  memcpy(ip_hdr, recv_ip_hdr, ntohs(recv_ip_hdr->ip_len));

  if (type == 3) {
    sr_icmp_t3_hdr_t* icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Fill out the ICMP headers */
    icmp_t3_hdr->icmp_type = type;
    icmp_t3_hdr->icmp_code = code;
    icmp_t3_hdr->unused = 0;
    memcpy(icmp_t3_hdr->data, recv_ip_hdr, ICMP_DATA_SIZE);
    icmp_t3_hdr->icmp_sum = 0;
    icmp_t3_hdr->icmp_sum = cksum((uint8_t *)icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
  } else {
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum((uint8_t *)icmp_hdr, sizeof(sr_icmp_hdr_t));
  }

  /* Fill out the IP headers */
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_dst = recv_ip_hdr->ip_src;
  ip_hdr->ip_sum = 0;

  if (code == 3) {
    ip_hdr->ip_src = recv_ip_hdr->ip_dst;
  } else {
    ip_hdr->ip_src = iface->ip;
  }

  if (type == 3) {
    ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));
  } else {
    ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, ip_hdr->ip_hl * sizeof(unsigned int));
  }

  /* sr_send_ip_packet will fill out the ethernet header */
  memset(ether_hdr->ether_dhost, 0x00, ETHER_ADDR_LEN);
  memset(ether_hdr->ether_shost, 0x00, ETHER_ADDR_LEN);
  ether_hdr->ether_type = htons(ethertype_ip);

  fprintf(stderr, "Wrapping ICMP header in ");
  print_hdrs(icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

  sr_send_ip_packet(sr, icmp_packet, match->gw.s_addr, sizeof(sr_ethernet_hdr_t) + ntohs(recv_ip_hdr->ip_len), iface->name);
}

/* LPM: The Easy Way */
struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr, uint32_t ip_dst) {
  struct sr_rt* lpm_entry = NULL;
  int longest_match_bits = 0;
  struct sr_rt* cur_entry = sr->routing_table;
  while (cur_entry) {
    uint32_t mask = ntohl(cur_entry->mask.s_addr);
    uint32_t dest = ntohl(cur_entry->dest.s_addr);
    int matched_bits = 0;
    int all_matched = 1;

    int i = 31;

    /* bit shifting magic */
    while (all_matched && ((mask & 1 << i) >> i) && i >= 0) {
      int bit_1 = ((ip_dst & 1 << i) >> i);
      int bit_2 = ((dest & 1 << i) >> i);

      if (bit_1 == bit_2) {
        matched_bits++;
        i--;
      } else {
        all_matched = 0;
        break;
      }
    }

    if (matched_bits > longest_match_bits || all_matched) {
        lpm_entry = cur_entry;
        longest_match_bits = matched_bits;
    }

    cur_entry = cur_entry->next;
  }

  printf("Matched %d bits\n", longest_match_bits);
  if (longest_match_bits < 24) {
    printf("Now do I fail?\n", longest_match_bits);
    return NULL;
  }

  printf("Matched entry is: ");
  print_addr_ip(lpm_entry->dest);
  return lpm_entry;
}
