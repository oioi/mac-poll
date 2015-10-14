#ifndef MACC_MAIN_H
#define MACC_MAIN_H

#include <boost/interprocess/interprocess_fwd.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <vector>
#include <unordered_map>
#include <unordered_set>

struct hostdata
{
   enum { ipv4_maxlen = 16, snmp_comm_maxlen = 128 };

   char ip[ipv4_maxlen];
   char community[snmp_comm_maxlen];

   hostdata(const char *ip_, const char *comm_)
   {
      strncpy(ip, ip_, ipv4_maxlen);
      strncpy(community, comm_, snmp_comm_maxlen);
   }
};

/* Used to synchronise jobs between poller-processes.
 * Dataptr holds pointer to a memory region, holding sequence of hostdatas to poll. */
struct syncdata
{
   FILE *outfile {};
   hostdata *dataptr {};

   boost::interprocess::interprocess_mutex mlock;
};

struct macdata
{
   oid mac[6];
   uint_t port;
   uint_t vlan;

   macdata(oid *mac_, uint_t port_, uint_t vlan_) :
      port{port_}, vlan{vlan_} { memmove(mac, mac_, sizeof(mac)); }
};

/* Defines SNMP interface mapping for concrete device type. */
enum class maptype
{
   plain,       // device ifIndexes map directly to physical interface numbers. 
   mapped       // device ifNames must be polled to determine actual map ifIndex -> ifName.
};

/* Device-type specific information. */
struct deviceinfo
{
   size_t oidlen;                       // length of mac_table_oid.
   oid mac_table_oid[MAX_OID_LEN];      // OID to request fdb table from the switch of this type.

   size_t mac_offset;                   // offset from the start of response OID to the first MAC byte.
   size_t vlan_offset;                  // offset from the start of response OID to the VLAN number.

   maptype intmap;
};

/* Device polling state - used by SNMP callback and poller */
enum class pollstate {
   initial,                     // obviously initial state
   retry,                       // retry with default community
   retry_initial,               // we tried with default community

   polling_iftype,              // polling iftypes (only if mapped maptype)
   polling_ifname,              // polling ifnames  (only if mapped maptype)
   polling_macs,                // polling mac-address table
   abort,                       // something happened in process. done, but assuming data might be wrong
   finished                     // we're done
};

using devinfo_c = std::unordered_map<std::string, deviceinfo>;
using intmap_c = std::unordered_map<uint_t, std::string>;

struct polldata
{
   hostdata *hdata {};
   snmp_session *sess {};
   deviceinfo *devinfo {};
   pollstate pstate {pollstate::initial};

   intmap_c intmap;
   std::vector<macdata> macs;
   std::unordered_set<uint_t> ignore_ports;   

   size_t oidlen;   
   oid current_oid[MAX_OID_LEN];

   polldata(hostdata *hdata_) : hdata{hdata_} { }
};

struct statistics
{
   uint_t total_devices {};
   uint_t aborted_devices {};
   uint_t interr_devices {};
   uint_t recv_mac_count {};
   uint_t save_mac_count {};
};

#endif
