#CS118 Router Documentation
##To Do
* `sr_init` - initialize router
* `sr_handlepacket` - deal with each received packet
* `srp_arpcache_sweepreqs` - called every second, determine whether to resend or destroy arp requests
* `handle_arpreq` - handle sending arp requests if necessary (more info in `sr_arpcache` section)

##`sr_utils`
###`uint16_t cksum(const void *_data, int len)`
* computes a checksum for the given buffer of `len` bytes

###`uint16_t ethertype(uint8_t *buf)`
* returns ethernet type if `buf` is an ethernet header

###`uint8_t ip_protocol(uint8_t *buf)`
* returns the ip protocol if `buf` is an ip header

###`void print_addr_eth(uint8_t *addr)`
* prints out formatted ethernet address, e.g. `00:11:22:33:44:55`

###`void print_addr_ip(struct in_addr address)`
* prints out ip address as a string from an `in_addr`

###`void print_addr_ip_int(uint32_t ip)`
* prints out ip address from integer value

###` void print_hdr_ip(uint8_t *buf)`
* prints out fields in ip header

###`void print_hdr_icmp(uint8_t *buf)`
* prints out icmp headers (internet control message protocol)

###`void print_hdr_arp(uint8_t *buf)`
* prints out arp headers

###`void print_hdrs(uint8_t *buf, uint32_t length)`
* prints out all headers, starting from ethernet

##`sr_rt`
###`struct sr_rt`
* represents a single node in the routing table (linked list)

###`int sr_load_rt(struct sr_instance*, const char*)`
* loads routing table from server

###`void sr_add_rt_entry(struct sr_instance* sr, struct in_addr dest, struct in_addr gw, struct in_addr mask,char* if_name)`
* inserts a new routing table node with given destination, gateway, mask, interface

###`void sr_print_routing_table(struct sr_instance* sr)`
* prints out current routing table

###`void sr_print_routing_entry(struct sr_rt* entry)`
* prints out a routing table node

##`sr_if`
###`struct sr_if`
* represents a single node in the interface list (linked list)

###`struct sr_if* sr_get_interface(struct sr_instance* sr, const char* name)`
* add an interface to the router's list

###`void sr_set_ether_addr(struct sr_instance* sr, const unsigned char* addr)`
* set ethernet address of LAST interface in interface list

###`void sr_set_ether_ip(struct sr_instance* sr, uint32_t ip_nbo)`
* set ip address of LAST interface in the interface list

###`void sr_print_if_list(struct sr_instance* sr)`
* prints out current interface list

###`void sr_print_if(struct sr_if* iface)`
* prints out an interface list node

##`sr_dumper`
###`struct pcap_file_header`
* represents the file header. contains magic number, version number (major/minor), local timezone, timestamp accuracy, maximum length saved portion of each packet, and data link type

###`struct pcap_pkthdr`
* represents packet header. contains timestamp, length of present portion, and length of packet off wire

###`struct pcap_timeval`
* represents dumpfile timeval. contains second and microsecond values.

###`struct pcap_sf_pkthdr`
* how a packet header is actually stored in the dumpfile. contains timestamp (as `pcap_timeval`), length of present portion, and length of packet off wire

###`FILE* sr_dump_open(const char *fname, int thiszone, int snaplen)`
* open and initialize a dumpfile

###`void sr_dump(FILE *fp, const struct pcap_pkthdr *h, const unsigned char *sp)`
* write information into a logfile

###`void sr_dump_close(FILE *fp)`
* close the dumpfile'

##`sr_arpcache`
###`struct sr_packet`
* represents a packet. contains a raw ethernet frame, length of frame, outgoing interface, and reference to next packet

###`struct sr_arpentry`
* represents an arp entry. contains mac, ip address in network byte order, time added, and valid field

###`struct sr_arpreq`
* represents an arp request. contains ip, last time sent, number of times sent, list of packets waiting on this request to finish, and a pointer to the next request

###`struct sr_arpcache`
* represents the arp cache. contains array of arp entries, pointer to list of arp requests, and pthread mutex locks and attributes

###`struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip)`
* checks if an ip->mac mapping is in the cache. ip in network byte order. free the returned arp entry manually if not NULL

###`struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache, uint32_t ip, uint8_t *packet, unsigned int packet_len, char *iface)`
* add an arp request to the queue. if the request is already in the queue, adds the packet to the linked list for the `sr_arpreq` that corresponds to this request. a pointer to the arp request is returned and must be manually freed.
* the request can be removed from the queue with `sr_arpreq_destroy`

###`struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache, unsigned char *mac, uint32_t ip)`
* looks up ip in the request queue and returns a pointer to the corresponding `sr_arpreq` if found
* inserts ip->mac mapping in the cache and marks as valid

###`void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry)`
* frees all memory associated with the arp request entry and removes it from any queues

###`void sr_arpcache_dump(struct sr_arpcache *cache)`
* prints out the arp table

###Using `sr_arpcache`
#### When sending packet to next_hop_ip
    entry = arpcache_lookup(next_hop_ip)

    if entry:
        use next_hop_ip->mac mapping in entry to send the packet
        free entry
    else:
        req = arpcache_queuereq(next_hop_ip, packet, len)
        handle_arpreq(req)

The `handle_arpreq()` function is a function you should write, and it should
handle sending ARP requests if necessary:

    function handle_arpreq(req):
        if difftime(now, req->sent) > 1.0
            if req->times_sent >= 5:
                send icmp host unreachable to source addr of all pkts waiting on this request
                arpreq_destroy(req)
            else:
                send arp request
                req->sent = now
                req->times_sent++

The ARP reply processing code should move entries from the ARP request
queue to the ARP cache:

#### When servicing an arp reply that gives us an IP->MAC mapping
    req = arpcache_insert(ip, mac)

    if req:
        send all packets on the req->packets linked list
        arpreq_destroy(req)
