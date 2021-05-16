#include "logic.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);

	RoutingTable_t routing_table = routing_table_initialize(argv[1]);
	RoutingTableEntry_t *routing_entry;

	ARPTable_t arp_table = arp_table_initialize();
	ARPTableEntry_t *arp_entry;

	uint32_t pkt_intf_ip;
	uint8_t pkt_intf_mac[6];

	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;
	struct arp_header *arp_hdr;
	struct icmphdr *icmp_hdr;

	queue waiting_queue = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		/* Students will write code here */

		eth_hdr = (struct ether_header *)m.payload;

		pkt_intf_ip = inet_addr(get_interface_ip(m.interface));
		get_interface_mac(m.interface, pkt_intf_mac);

		// ARP packet handling
		if ((arp_hdr = parse_arp(m.payload)) != NULL && pkt_intf_ip == arp_hdr->tpa) {

			// Update ARP table (if necessary)
			arp_table_update(&arp_table, arp_hdr->spa, arp_hdr->sha);

			// If message type is ARP request, send ARP reply back
			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
				memcpy(eth_hdr->ether_shost, pkt_intf_mac, 6 * sizeof(uint8_t));
				send_arp(arp_hdr->spa, pkt_intf_ip, eth_hdr, m.interface, htons(ARPOP_REPLY));

			// If message type is ARP reply, check the waiting queue for packets to be sent
			} else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {

				queue verified_queue = queue_create();
				WaitingPacket_t *wp;

				while (!queue_empty(waiting_queue)) {
					wp = queue_deq(waiting_queue);

					// Send packets based on the information from the ARP reply
					if (wp->next_dest_ip == arp_hdr->spa) {
						eth_hdr = (struct ether_header *)((wp->pkt)->payload);
						memcpy(eth_hdr->ether_dhost, arp_hdr->sha, 6 * sizeof(uint8_t));
						memcpy(eth_hdr->ether_shost, arp_hdr->tha, 6 * sizeof(uint8_t));
						send_packet(m.interface, wp->pkt);
					} else {
						queue_enq(verified_queue, wp);
					}
				}

				// Put back in the waiting queue the packets that can't be sent yet
				while (!queue_empty(verified_queue))
        			queue_enq(waiting_queue, queue_deq(verified_queue));
			}

			continue;
		}

		// IP packet handling
		if ((ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header))) != NULL) {
			
			// IP header TTL update and checksum verification
			if (iphdr_update(eth_hdr, ip_hdr, m.interface) != 0)
				continue;

			// ICMP packet handling
			if ((icmp_hdr = parse_icmp(m.payload)) != NULL) {

				// ICMP header checksum verification
				uint16_t chksum = icmp_hdr->checksum;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum = icmp_checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

				if (chksum != icmp_hdr->checksum)
					continue;

				// If message type is echo request, send echo reply back
				if ((ip_hdr->daddr == pkt_intf_ip) && (icmp_hdr->type == ICMP_ECHO)) {
					send_icmp(ip_hdr->saddr, ip_hdr->daddr, pkt_intf_mac, eth_hdr->ether_shost,
						ICMP_ECHOREPLY, 0, m.interface, icmp_hdr->un.echo.id, 1);
					continue;
				}
			}

			// Destination unreachable
			if ((routing_entry = routing_table_query(&routing_table, ip_hdr->daddr)) == NULL) {
				send_icmp_error(ip_hdr->saddr, pkt_intf_ip, pkt_intf_mac, eth_hdr->ether_shost,
					ICMP_DEST_UNREACH, ICMP_NET_UNREACH, m.interface);
				continue;
			}

			memcpy(eth_hdr->ether_shost, pkt_intf_mac, 6 * sizeof(uint8_t));

			// Unknown MAC: put packet in waiting queue and send an ARP request (if necessary)
			if ((arp_entry = arp_table_query(&arp_table, routing_entry->next_hop)) == NULL) {

				WaitingPacket_t *wp = make_waiting_packet(routing_entry->next_hop, &m);

				// Check if an ARP request was already sent
				if (arp_request_sent(waiting_queue, routing_entry->next_hop) < 0) {
					eth_hdr->ether_type = htons(ETHERTYPE_ARP);
					memset(eth_hdr->ether_dhost, 0xff, 6 * sizeof(uint8_t));

					send_arp(routing_entry->next_hop,
						inet_addr(get_interface_ip(routing_entry->interface)),
						eth_hdr, routing_entry->interface, htons(ARPOP_REQUEST));
				}

				queue_enq(waiting_queue, wp);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6 * sizeof(uint8_t));
			send_packet(routing_entry->interface, &m);
		}
	}
}
