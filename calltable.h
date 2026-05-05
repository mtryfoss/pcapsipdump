/*
    This file is part of pcapsipdump

    pcapsipdump is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    pcapsipdump is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Foobar; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    ---

    Project's home: http://pcapsipdump.sf.net/
*/

#ifndef INT32_MAX
#define INT32_MAX (2147483647)
#endif

#include <vector>
#include <string>
#include <map>

#include <pcap.h>
#include <arpa/inet.h>

#define calltable_max_ip_per_call 4

struct addr_addr_id
{
    in_addr_t saddr;
    in_addr_t daddr;
    uint16_t id;
};

struct calltable_element
{
    unsigned char is_used;
    unsigned char had_bye;
    unsigned char had_t38;
    unsigned char rtpmap_event;
    char caller[16];
    char callee[16];
    char call_id[256];
    unsigned long call_id_len;
    in_addr_t ip[calltable_max_ip_per_call];
    uint16_t port[calltable_max_ip_per_call];
    uint32_t ssrc[calltable_max_ip_per_call];
    int ip_n;
    time_t first_packet_time;
    time_t last_packet_time;
    pcap_dumper_t *f_pcap;
    char fn_pcap[128];
    struct addr_addr_id last_aai;
};


#ifdef USE_CALLTABLE_CACHE
struct addr_port
{
    in_addr_t addr;
    uint16_t port;
};
struct ce_irtp_ssrc
{
    calltable_element *ce;
    int irtp;
    uint32_t ssrc;
};
#endif

struct pending_fragment
{
    struct pcap_pkthdr header;
    std::vector<u_char> data;
};

struct pending_frag_stream
{
    struct addr_addr_id aai;
    std::vector<pending_fragment> packets;
    time_t first_seen;
    bool has_first_fragment; // fragment with offset==0 seen?
};

class calltable
{
public:
    calltable();
    int add(
        const char *call_id,
        unsigned long call_id_len,
        const char *caller,
        const char *callee,
        time_t time);
    int find_by_call_id(
        const char *call_id,
        unsigned long call_id_len);
    int add_ip_port(
        calltable_element *ce,
        in_addr_t addr,
        unsigned short port);
    int find_ip_port(
        in_addr_t addr,
        unsigned short port);
    int find_ip_port_ssrc(
        in_addr_t addr,
        unsigned short port,
        uint32_t ssrc,
        calltable_element **ce,
        int *idx_rtp);
    int find_all_ip_port_ssrc(
        in_addr_t addr,
        unsigned short port,
        uint32_t ssrc,
        std::vector<calltable_element *> &matches);
    void add_ipfrag(
        struct addr_addr_id aai,
        pcap_dumper_t *f);
    void delete_ipfrag(
        struct addr_addr_id aai);
    pcap_dumper_t *get_ipfrag(
        struct addr_addr_id aai);
    int do_cleanup(time_t currtime);
    void buffer_frag(struct addr_addr_id aai,
                     const struct pcap_pkthdr *hdr,
                     const u_char *data);
    void flush_frags(struct addr_addr_id aai,
                     pcap_dumper_t *f,
                     bool packet_buffered);
    void expire_frags(time_t now, int max_age_seconds);
    pending_frag_stream *get_frags(struct addr_addr_id aai);
    void delete_frags(struct addr_addr_id aai);
    int find_by_aai(struct addr_addr_id aai);
    std::vector<calltable_element> table;
    std::map<addr_addr_id, pcap_dumper_t *> ipfrags;
    std::map<std::tuple<uint32_t, uint32_t, uint16_t>, pending_frag_stream> frag_buffer;
    bool erase_non_t38;
    int opt_absolute_timeout;

private:
    time_t global_last_packet_time;
#ifdef USE_CALLTABLE_CACHE
    std::map<addr_port, ce_irtp_ssrc> cache;
    std::map<std::string, int> call_id_cache;
#endif
};

bool aai_equal(const struct addr_addr_id &a, const struct addr_addr_id &b);