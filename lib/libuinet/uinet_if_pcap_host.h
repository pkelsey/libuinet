/*
 * Copyright (c) 2015 Patrick Kelsey. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _UINET_IF_PCAP_HOST_H_
#define _UINET_IF_PCAP_HOST_H_

struct if_pcap_host_context;

typedef void (*if_pcap_handler)(void *ctx, const uint8_t *buf, unsigned int size);

struct if_pcap_host_context * if_pcap_create_handle(const char *rx_ifname, unsigned int rx_isfile, int *rx_fd, unsigned int rx_isnonblock,
						    const char *tx_ifname, unsigned int tx_isfile, unsigned int tx_file_snaplen,
						    unsigned int tx_file_per_flow, unsigned int tx_file_concurrent_flows, unsigned int tx_file_dirbits,
						    uint32_t tx_file_epoch_no, uint32_t tx_file_instance_index);
void if_pcap_destroy_handle(struct if_pcap_host_context *ctx);
int if_pcap_sendpacket(struct if_pcap_host_context *ctx, const uint8_t *buf, unsigned int size,
		       uint64_t flowid, uint64_t ts_nsec);
void if_pcap_flushflow(struct if_pcap_host_context *ctx, uint64_t flowid);
int if_pcap_getpacket(struct if_pcap_host_context *ctx, uint64_t now,
		      uint32_t *buffer, uint16_t max_length, uint16_t *length,
		      uint64_t *timestamp, uint64_t *wait_ns);

#endif /* _UINET_IF_PCAP_HOST_H_ */
