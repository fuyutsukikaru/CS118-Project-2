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
#include "sr_arpcache.h"
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

  /* fill in code here */

  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to load ethernet header, insufficient length\n");
    return;
  }

  uint16_t et = ethertype(packet);

  /* Handle IP protocol */
  if (et == ethertype_ip) {
    minlength += sizeof(sr_ip_hdr_t);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t ipsum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0; /* checksum field is assumed to be 0 for calculation */
    uint32_t cks = cksum(ip_hdr, ip_hdr->ip_hl * sizeof(unsigned int));

    print_hdr_ip(packet);
    print_addr_ip(sr->routing_table->dest);
    print_addr_ip_int(ntohs(ip_hdr->ip_dst));
    printf("Routing Table is: ");
    sr_print_routing_table(sr);

    if (len < minlength) {
      fprintf(stderr, "Failed to load IP header, insufficient length\n");
      return;
    } else if (ipsum != cks) {
      fprintf(stderr, "Checksum mismatch\n");
      return;
    } else {

    }
  } else if (et == ethertype_arp) {
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "Failed to load ARP header, insufficient length\n");
      return;
    } else {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        print_hdr_arp(arp_hdr);
        sr_send_arp_reply(sr, arp_hdr, interface);
      } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {

      }
    }
  } else {
    fprintf(stderr, "Unrecognized type: %d", et);
  }
}/* end sr_ForwardPacket */

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
  reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
  reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
  reply_arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(reply_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip = iface->ip;
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

  print_hdr_arp(reply_arp_hdr);
  sr_send_packet(sr, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
  free(packet);
}

/* no one knows if this works */
struct in_addr sr_longest_prefix_match(uint32_t ip_dst, struct sr_rt* rt) {
  struct sr_rt* cur_entry = rt;

  /* bit shifting magic */
  uint32_t tokenized_ip_dst [4] = {0};
  tokenized_ip_dst[0] = ip_dst >> 24;
  tokenized_ip_dst[1] = (ip_dst << 8) >> 24;
  tokenized_ip_dst[2] = (ip_dst << 16) >> 24;
  tokenized_ip_dst[3] = (ip_dst << 24) >> 24;

  int rt_num_matches[10] = {0};
  size_t rt_index = 0;

  /* iterate through each entry in the routing table */
  while (cur_entry) {
    char cur_ip_dst[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(cur_entry->dest), cur_ip_dst, 100) == NULL) {
      fprintf(stderr,"inet_ntop error on address conversion\n");
    } else {
      int num_matches = 0;
      /* tokenize dest IP address */
      char cur_ip_digit = '\0';
      unsigned char ip_split[4] = {0};
      size_t byte_index = 0;
      size_t ip_index = 0;

      int still_matching = 1;

      while (cur_ip_digit = *(cur_ip_dst+ip_index)) {
        if (isdigit((unsigned char) cur_ip_digit)) {
          ip_split[byte_index] *= 10;
          ip_split[byte_index] += cur_ip_digit - '0';
        } else {
          /* test for a match */
          if (tokenized_ip_dst[byte_index] == (uint32_t) ip_split[byte_index] && still_matching) {
            num_matches++;
          } else {
            still_matching = 0;
          }
          byte_index++;
        }
        ip_index++;
      }

      rt_num_matches[rt_index] = num_matches;
      rt_index++;
    }
    cur_entry = cur_entry->next;
  }

  /* find the index of the longest prefix matching entry */
  int index_max = 0;
  int i = 1;
  for (; i < sizeof(rt_num_matches) / sizeof(rt_num_matches[0]); i++) {
    if (rt_num_matches[i] > rt_num_matches[index_max]) {
      index_max = i;
    }
  }

  /* return the destination address of that entry */
  cur_entry = rt;
  int cur_index = 0;
  while (cur_entry) {
    if (cur_index == index_max) {
      return cur_entry->dest;
    }
    cur_entry = cur_entry->next;
  }
}
