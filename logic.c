#include "logic.h"

// Function used to compare routing entries, used to sort the table
int routing_entries_comparator(const void *a, const void *b) {
    const RoutingTableEntry_t **aa = (const RoutingTableEntry_t **)a;
    const RoutingTableEntry_t **bb = (const RoutingTableEntry_t **)b;
    return ntohl((*aa)->prefix & (*aa)->mask) - ntohl((*bb)->prefix & (*bb)->mask);
}

// Creates a new entry for the routing table
RoutingTableEntry_t *make_routing_entry(uint32_t prefix, uint32_t next_hop,
    uint32_t mask, int interface) {
        
    RoutingTableEntry_t *entry = malloc(sizeof(RoutingTableEntry_t));
    entry->prefix = prefix;
    entry->next_hop = next_hop;
    entry->mask = mask;        
    entry->interface = interface;
    return entry;
}

// Reads the routing table from a file and puts it into memory
void routing_table_reader(FILE *fp, RoutingTable_t *table) {
    char *prefix = calloc(16, sizeof(*prefix));
    char *next_hop = calloc(16, sizeof(*next_hop));
    char *mask = calloc(16, sizeof(*mask));
    int interface;

    while (4 == fscanf(fp, "%s %s %s %d", prefix, next_hop, mask, &interface)) {
        if (table->num_of_entries == table->capacity) {
            table->capacity *= 2;
            table->entries = realloc(table->entries,
                table->capacity * sizeof(*(table->entries)));
        }

        table->entries[table->num_of_entries] = make_routing_entry(
            inet_addr(prefix), inet_addr(next_hop), inet_addr(mask), interface);

        table->num_of_entries++;
    }
}

RoutingTable_t routing_table_initialize(char *routing_table_file_path) {
	FILE *fp = fopen(routing_table_file_path, "r");
    DIE(fp == NULL, "routing_table_file");

    RoutingTable_t table;
    table.capacity = 256;
    table.num_of_entries = 0;
    table.entries = calloc(table.capacity, sizeof(*(table.entries)));

    routing_table_reader(fp, &table);

    // Sorting is performed on the table for O(logN) access
    qsort(table.entries, table.num_of_entries, sizeof(*(table.entries)),
        routing_entries_comparator);
	
    fclose(fp);
    return table;
}

ARPTableEntry_t *make_arp_entry(uint32_t ip, uint8_t *mac) {
    ARPTableEntry_t *entry = malloc(sizeof(ARPTableEntry_t));
    entry->ip = ip;
    memcpy(entry->mac, mac, 6 * sizeof(uint8_t));
    return entry;
}

void arp_table_update(ARPTable_t *table, uint32_t ip, uint8_t *mac) {
    DIE(table == NULL, "arp_table_bad_update");

    if (table->entries != NULL) {
        if (arp_table_query(table, ip) != NULL)
            return;
    
        if (table->num_of_entries == table->capacity) {
            table->capacity *= 2;
            table->entries = realloc(table->entries,
                table->capacity * sizeof(*(table->entries)));
        }

    } else {
        table->entries = calloc(table->capacity, sizeof(*(table->entries)));
    }

    table->entries[table->num_of_entries] = make_arp_entry(ip, mac);

    table->num_of_entries++;
}

ARPTableEntry_t *arp_table_query(ARPTable_t *table, uint32_t ip) {
    DIE(table == NULL, "arp_table_bad_query");

    if (table->entries == NULL)
        return NULL;

    int i;
    for (i = 0; i < table->num_of_entries; i++)
        if (table->entries[i]->ip == ip)
            return table->entries[i];

    return NULL;
}

ARPTable_t arp_table_initialize() {
    ARPTable_t arp_table;
    arp_table.num_of_entries = 0;
    arp_table.capacity = 1;
    arp_table.entries = NULL;
    return arp_table;
}

RoutingTableEntry_t *routing_table_query(RoutingTable_t *table, uint32_t ip) {
    DIE(table == NULL, "routing_table_bad_query");

    RoutingTableEntry_t *entry = NULL;
    int left = 0, right = table->num_of_entries;
    int middle = (left + right) / 2;

    // Binary search gives the best entry in approximately O(logN) time
    while (left <= right) {
        if (ntohl(ip & table->entries[middle]->mask) ==
            ntohl(table->entries[middle]->prefix)) {

            if (entry == NULL) {
                entry = table->entries[middle];
            } else if (ntohl(table->entries[middle]->mask) > ntohl(entry->mask)) {
                entry = table->entries[middle];
            }

            // Search for better (more specific) entries higher up in the table
            right = middle - 1;
            
        } else
        if (ntohl(ip & table->entries[middle]->mask) >
            ntohl(table->entries[middle]->prefix)) {

            left = middle + 1;
        } else
        if (ntohl(ip & table->entries[middle]->mask) <
            ntohl(table->entries[middle]->prefix)) {

            right = middle - 1;
        }

        middle = (left + right) / 2;
    }
    
    return entry;
}

void packet_time_exceeded(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int intf) {
    uint32_t ip = inet_addr(get_interface_ip(intf));
    uint8_t mac[6];
    get_interface_mac(intf, mac);

    send_icmp_error(ip_hdr->saddr, ip, mac, eth_hdr->ether_shost,
        ICMP_TIME_EXCEEDED, 0, intf);
}

int iphdr_update(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int intf) {
    // Checksum verification
    uint16_t chksum = ip_hdr->check;
    ip_hdr->check = 0;
    if (chksum != ip_checksum(ip_hdr, sizeof(struct iphdr)))
        return -2;

    // TTL update
    ip_hdr->ttl--;
    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

    // Drop packet and send back time exceeded error if TTL expired
    if (ip_hdr->ttl <= 0) {
        packet_time_exceeded(eth_hdr, ip_hdr, intf);
        return -1;
    }
    
    return 0;
}

// Returns -1 if no ARP request was sent and N-1 if N packets are waiting for an ARP reply 
int arp_request_sent(queue waiting_queue, uint32_t next_dest_ip) {
    queue verified_queue = queue_create();
    WaitingPacket_t *wp;
    int packets_waiting = -1;

    while (!queue_empty(waiting_queue)) {
        wp = queue_deq(waiting_queue);
        if (wp->next_dest_ip == next_dest_ip)
            packets_waiting++;

        queue_enq(verified_queue, wp);
    }

    while (!queue_empty(verified_queue))
        queue_enq(waiting_queue, queue_deq(verified_queue));

    return packets_waiting;
}

WaitingPacket_t *make_waiting_packet(uint32_t next_dest_ip, packet *pkt) {
    WaitingPacket_t *wp = malloc(sizeof(WaitingPacket_t));
    wp->next_dest_ip = next_dest_ip;
    wp->pkt = malloc(sizeof(packet));
    memcpy(wp->pkt, pkt, sizeof(packet));
    return wp;
}
