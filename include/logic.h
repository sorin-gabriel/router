/*
    SORIN-GABRIEL MATEESCU
    322CB

    Tema 1 PCom
*/

#include "skel.h"
#include "queue.h"

// Routing entry definition
typedef struct {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed)) RoutingTableEntry_t;

// Routing table definition
typedef struct {
	int num_of_entries;
	int capacity;
	RoutingTableEntry_t **entries;
} __attribute__((packed)) RoutingTable_t;

// Initialize the routing table
RoutingTable_t routing_table_initialize(char *input_file);

// Query the routing table
RoutingTableEntry_t *routing_table_query(RoutingTable_t *table, uint32_t ip);


// ARP entry definition
typedef struct {
    uint32_t ip;
    uint8_t mac[6];
} __attribute__((packed)) ARPTableEntry_t;

// ARP table definition
typedef struct {
    int num_of_entries;
    int capacity;
    ARPTableEntry_t **entries;
} __attribute__((packed)) ARPTable_t;

// Initialize the ARP table
ARPTable_t arp_table_initialize();

// Query the ARP table
ARPTableEntry_t *arp_table_query(ARPTable_t *table, uint32_t ip);

// Update the ARP table
void arp_table_update(ARPTable_t *table, uint32_t ip, uint8_t *mac);

// Check if an ARP request was sent
int arp_request_sent(queue waiting_queue, uint32_t next_dest_ip);

// Waiting packet definition
typedef struct {
	uint32_t next_dest_ip;
	packet *pkt;
}  __attribute__((packed)) WaitingPacket_t;

// Create a waiting packet from a normal packet
WaitingPacket_t *make_waiting_packet(uint32_t next_dest_ip, packet *pkt);

// Update the IP header
int iphdr_update(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int interface);