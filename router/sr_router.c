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

  if (et == ethertype_ip) {
    minlength += sizeof(sr_ip_hdr_t);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint16_t ipsum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0; /* checksum field is assumed to be 0 for calculation */
    uint32_t cks = cksum(ip_hdr, ip_hdr->ip_hl * sizeof(unsigned int));

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
        struct sr_arpreq* req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (req) {
          struct sr_packet* pkt = req->packets;
          struct sr_arpentry* entry;
          struct sr_if* iface = sr_get_interface(sr, interface);
          while (pkt) {
            entry = sr_arpcache_lookup(&sr->cache, req->ip);
            if (entry) {
              sr_ethernet_hdr_t* ether_hdr = (sr_ethernet_hdr_t *)(pkt->buf);
              memcpy(ether_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
              memcpy(ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

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

