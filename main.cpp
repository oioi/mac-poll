#include <boost/tokenizer.hpp>
#include <sys/mman.h>
#include <mutex>
#include <chrono>
#include <list>

#include "prog_config.h"
#include "aux_log.h"

#include "main.h"

namespace {
   const char *progname = "mac-collector";
   const char *conffile = "macc.conf";

   conf::config_map snmp_section {
      { "bulk-maxrep", { conf::val_type::integer          } },
      { "community",   { conf::val_type::string           } },   // default one
      { "max-hosts",   { conf::val_type::integer          } },
      { "ignore-vlan", { conf::val_type::integer          } },   // actually needs to be multiple integers
      { "timeout",     { conf::val_type::integer, 1000000 } }    // uS
   };

   const oid ifType[] { 1, 3, 6, 1, 2, 1, 2, 2, 1, 3 };
   const oid ifName[] { 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1 };

   statistics pollstat;
}

conf::config_map config {
   { "macpath", { conf::val_type::string  } },
   { "iplist",  { conf::val_type::string  } },
   { "pollers", { conf::val_type::integer } },
   { "snmp",    { conf::val_type::section, &snmp_section } }
};

devinfo_c devinfo {
   { ".1.3.6.1.4.1.2011.2.23.88",       // Huawei s2309
      { 15, { 1, 3, 6, 1, 4, 1, 2011, 5, 25, 42, 2, 1, 33, 1, 13 }, 21, 15, maptype::mapped } },

   { ".1.3.6.1.4.1.2011.2.23.92",       // Huawei s2326
      { 15, { 1, 3, 6, 1, 4, 1, 2011, 5, 25, 42, 2, 1, 33, 1, 13 }, 21, 15, maptype::mapped } },

   { ".1.3.6.1.4.1.171.10.64.1",       // DES-3526
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.105.1",      // DES-3528
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.64.2",       // DES-3550
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.63.2",       // DES-3018
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.63.3",       // DES-3026
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.63.6",       // DES-3028
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.48.1",       // DES-3226s
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },

   { ".1.3.6.1.4.1.171.10.113.1.1",       // DES-3200-10
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.1.2",       // DES-3200-18
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.1.5",       // DES-3200-26
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.1.3",       // DES-3200-28
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.1.4",       // DES-3200-28F
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },

   { ".1.3.6.1.4.1.171.10.113.2.1",       // DES-3200-10C
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.3.1",       // DES-3200-18C
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.4.1",       // DES-3200-26C
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.5.1",       // DES-3200-28C
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },
   { ".1.3.6.1.4.1.171.10.113.6.1",       // DES-3200-28FC
      { 13, { 1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2 }, 14, 13, maptype::plain } },      
};

void prepare_outdir(syncdata *sdata)
{
   static const char *funcname {"prepare_outdir"};

   struct stat stbuf;   
   buffer path;
   time_t rawtime = time(nullptr);
   tm *timeinfo = localtime(&rawtime);

   umask(S_IWGRP | S_IWOTH | S_IROTH | S_IXOTH);
   path.print("%s/%u", config["macpath"].get<conf::string_t>().c_str(), timeinfo->tm_year + 1900);
   if (-1 == stat(path.data(), &stbuf))
   {
      if (ENOENT == errno) mkdir(path.data(), S_IRWXU | S_IRGRP | S_IXGRP);
      else logger.error_exit(funcname, "Error while trying to obtain directory '%s' stats: %s", path.data(), strerror(errno));
   }

   path.append("/%02u-%u", timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
   if (-1 == stat(path.data(), &stbuf))
   {
      if (ENOENT == errno) mkdir(path.data(), S_IRWXU | S_IRGRP | S_IXGRP);
      else logger.error_exit(funcname, "Error while trying to obtain directory '%s' stats: %s", path.data(), strerror(errno));
   }

   path.append("/%02u-%02u-%u.desmac", timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
   if (nullptr == (sdata->outfile = fopen(path.data(), "a")))
      logger.error_exit(funcname, "Couldn't open output file '%s' for append writing: %s", path.data(), strerror(errno));
   setvbuf(sdata->outfile, nullptr, _IOLBF, 0);   
}

void prepare_data(syncdata *sdata)
{
   const char *funcname {"prepare_data"};
   const conf::string_t &filename {config["iplist"].get<conf::string_t>()};
   const conf::string_t &community {config["snmp"]["community"].get<conf::string_t>()};

   std::ifstream indata {filename};
   if (!indata) logger.error_exit(funcname, "Cannot open input devices file '%s': %s", filename.c_str(), strerror(errno));

   unsigned count = std::count(std::istreambuf_iterator<char>(indata), std::istreambuf_iterator<char>(), '\n');
   void *addr = mmap(nullptr, sizeof(hostdata) * (count + 1), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (MAP_FAILED == addr) logger.error_exit(funcname, "hostdata mmap() failed: %s", strerror(errno));
   sdata->dataptr = static_cast<hostdata *>(addr);

   indata.seekg(0, indata.beg);
   hostdata *ptr = sdata->dataptr;

   unsigned i;
   std::string ipstr, commstr, instr;
   boost::char_separator<char> sep {" \t\n"};

   while (std::getline(indata, instr))
   {
      i = 0;
      boost::tokenizer<boost::char_separator<char>> tokens {instr, sep};
      commstr.clear();

      for (const auto &tok : tokens)
      {
         switch (i) {
            case 0: ipstr = tok; break;
            case 1: commstr = tok; break;
         }
         i++;
      }

      if (0 == commstr.size()) commstr = community.c_str();
      new(ptr++) hostdata(ipstr.c_str(), commstr.c_str());
   }

   ptr->ip[0] = 0;
   if (indata.bad()) logger.error_exit(funcname, "Error while reading data: %s", strerror(errno));
   indata.close();
}

void print_mac_file(const syncdata &sdata, const polldata &pdata)
{
   time_t rawtime = time(nullptr);
   tm *timeinfo = localtime(&rawtime);
   const oid *ptr;

   for (const auto &entry : pdata.macs)
   {
      if (pdata.ignore_ports.end() != pdata.ignore_ports.find(entry.port)) continue;
      pollstat.save_mac_count++;
      ptr = entry.mac;

      fprintf(sdata.outfile, "mac %02lX:%02lX:%02lX:%02lX:%02lX:%02lX switch %s port ",
            *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5), pdata.hdata->ip);

      if (maptype::plain == pdata.devinfo->intmap) fprintf(sdata.outfile, "%lu ", entry.port);
      else fprintf(sdata.outfile, "%s ", pdata.intmap.find(entry.port)->second.c_str());

      fprintf(sdata.outfile, "vlan %lu [%02u:%02u:%02u %02u-%02u-%u]\n",
            entry.vlan, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
            timeinfo->tm_mday, timeinfo->tm_mon + 1, timeinfo->tm_year + 1900);
   }
}

void async_sendbulk(polldata *pdata, const oid *send_oid, size_t oidlen)
{
   static const char *funcname {"async_sendbulk"};
   static const unsigned maxrep = config["snmp"]["bulk-maxrep"].get<conf::integer_t>();

   netsnmp_pdu *req = snmp_pdu_create(SNMP_MSG_GETBULK);
   req->non_repeaters = 0;
   req->max_repetitions = maxrep;
   snmp_add_null_var(req, send_oid, oidlen);

   memmove(pdata->current_oid, send_oid, sizeof(oid) * oidlen);
   pdata->oidlen = oidlen;

   if (0 == snmp_send(pdata->sess, req))
   {
      int liberr, syserr;
      char *errstr;         
      snmp_error(pdata->sess, &liberr, &syserr, &errstr);
      logger.error_exit(funcname, "%s: snmp_send() failed: %s", pdata->hdata->ip, errstr);
   }
}

void handle_objid(snmp_pdu *pdu, polldata *pdata)
{
   static const char *funcname {"handle_objid"};
   static const size_t objid_strlen = 128;
   static char objid_string[objid_strlen] {};

   netsnmp_variable_list *vars = pdu->variables;
   if (ASN_OBJECT_ID != vars->type)
   {
      logger.log_message(LOG_WARNING, funcname, "%s: device returned an unexpected ASN type for sysObjID oid.", pdata->hdata->ip);
      pdata->pstate = pollstate::abort;
      return;
   }

   ssize_t len;
   if (-1 == (len = snprint_objid(objid_string, objid_strlen, vars->val.objid, vars->val_len / sizeof(oid))))
      logger.error_exit(funcname, "%s: snprint_objid() failed. buffer is not large enough?", pdata->hdata->ip);
   objid_string[len] = '\0';

   devinfo_c::iterator it;
   if (devinfo.end() == (it = devinfo.find(objid_string)))
   {
      logger.log_message(LOG_WARNING, funcname, "%s: unknown device type. objID: %s", pdata->hdata->ip, objid_string);
      pdata->pstate = pollstate::abort;
      return;
   }

   pdata->devinfo = &(it->second);
   switch (pdata->devinfo->intmap)
   {
      case maptype::plain:
         pdata->pstate = pollstate::polling_macs;
         async_sendbulk(pdata, pdata->devinfo->mac_table_oid, pdata->devinfo->oidlen);
         break;

      case maptype::mapped:
         pdata->pstate = pollstate::polling_iftype;
         async_sendbulk(pdata, ifType, sizeof(ifType) / sizeof(oid));
         break;

      default: logger.error_exit(funcname, "%s: unexpected maptype: %d", pdata->hdata->ip, static_cast<int>(pdata->devinfo->intmap));
   }
}

void handle_iftypes(snmp_pdu *pdu, polldata *pdata)
{
   static const char *funcname {"handle_iftypes"};
   netsnmp_variable_list *vars;

   enum interface_types {
      ethernetCsmacd = 6,
      gigabitEthernet = 117
   };

   for (vars = pdu->variables; nullptr != vars; vars = vars->next_variable)
   {
      if (netsnmp_oid_is_subtree(ifType, sizeof(ifType) / sizeof(oid), vars->name, vars->name_length) or
          0 == snmp_oid_compare(pdata->current_oid, pdata->oidlen, vars->name, vars->name_length))
      {
         async_sendbulk(pdata, ifName, sizeof(ifName) / sizeof(oid));
         pdata->pstate = pollstate::polling_ifname;
         return;
      }

      if (ASN_INTEGER != vars->type)
      {
         logger.log_message(LOG_WARNING, funcname, "%s: device returned an unexpected ASN type for ifType request.", pdata->hdata->ip);
         pdata->pstate = pollstate::abort;
         return;
      }

      if (nullptr == vars->next_variable) async_sendbulk(pdata, vars->name, vars->name_length);
      if (ethernetCsmacd == *(vars->val.integer) or gigabitEthernet == *(vars->val.integer))
         pdata->intmap.insert(std::make_pair(*(vars->name + (sizeof(ifType) / sizeof(oid))), ""));      
   }
}

void handle_ifnames(snmp_pdu *pdu, polldata *pdata)
{
   static const char *funcname {"handle_ifnames"};
   netsnmp_variable_list *vars;
   intmap_c::iterator it;

   for (vars = pdu->variables; nullptr != vars; vars = vars->next_variable)
   {
      if (netsnmp_oid_is_subtree(ifName, sizeof(ifName) / sizeof(oid), vars->name, vars->name_length) or
          0 == snmp_oid_compare(pdata->current_oid, pdata->oidlen, vars->name, vars->name_length))
      {
         pdata->pstate = pollstate::polling_macs;
         async_sendbulk(pdata, pdata->devinfo->mac_table_oid, pdata->devinfo->oidlen);
         return;
      }

      if (ASN_OCTET_STR != vars->type)
      {
         logger.log_message(LOG_WARNING, funcname, "%s: device returned an unexpected ASN type of ifName request.", pdata->hdata->ip);
         pdata->pstate = pollstate::abort;
         return;
      }

      if (pdata->intmap.end() == (it = pdata->intmap.find(*(vars->name + sizeof(ifName) / sizeof(oid))))) continue;
      it->second = reinterpret_cast<char *>(vars->val.string);
   }
}

void handle_macdata(snmp_pdu *pdu, polldata *pdata)
{
   static const char *funcname {"handle_macdata"};
   static const unsigned ignore_vlan = config["snmp"]["ignore-vlan"].get<conf::integer_t>();

   netsnmp_variable_list *vars;
   uint_t port, vlan;

   for (vars = pdu->variables; nullptr != vars; vars = vars->next_variable)
   {
      if (netsnmp_oid_is_subtree(pdata->devinfo->mac_table_oid, pdata->devinfo->oidlen, vars->name, vars->name_length) or
          0 == snmp_oid_compare(pdata->current_oid, pdata->oidlen, vars->name, vars->name_length))
      {
         pdata->pstate = pollstate::finished;
         return;
      }

      if (ASN_INTEGER != vars->type)
      {
         logger.log_message(LOG_WARNING, funcname, "%s: host returned non-integer answer for fdb table request.", pdata->hdata->ip);
         pdata->pstate = pollstate::abort;
         return;
      }

      pollstat.recv_mac_count++;
      port = *(vars->val.integer);
      if (nullptr == vars->next_variable) async_sendbulk(pdata, vars->name, vars->name_length);

      if (pdata->ignore_ports.end() != pdata->ignore_ports.find(port)) continue;
      vlan = *(vars->name + pdata->devinfo->vlan_offset);
      if (0 != port and ignore_vlan == vlan)
      {
         pdata->ignore_ports.insert(port);
         continue;
      }

      pdata->macs.emplace_back(vars->name + pdata->devinfo->mac_offset, port, vlan);
   }
}

int snmp_pdu_callback(int operation, snmp_session *, int, snmp_pdu *pdu, void *magic)
{
   static const char *funcname {"snmp_pdu_callback"};
   static const conf::string_t &community {config["snmp"]["community"].get<conf::string_t>()};
   polldata *pdata = static_cast<polldata *>(magic);

   if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE)
   {
      switch (pdata->pstate)
      {
         case pollstate::initial:
         case pollstate::retry_initial:
            handle_objid(pdu, pdata); break;

         case pollstate::polling_iftype: handle_iftypes(pdu, pdata); break;
         case pollstate::polling_ifname: handle_ifnames(pdu, pdata); break;
         case pollstate::polling_macs:   handle_macdata(pdu, pdata); break;
         default: logger.error_exit(funcname, "%s: unexpected pollstate: %d", pdata->hdata->ip, static_cast<int>(pdata->pstate));
      }
   }

   else
   {
      switch (pdata->pstate)
      {
         case pollstate::polling_iftype:
         case pollstate::polling_ifname:
         case pollstate::polling_macs:
            logger.log_message(LOG_INFO, funcname, "%s: device is not responding anymore. Giving up.", pdata->hdata->ip);
            pdata->pstate = pollstate::abort;
            pollstat.interr_devices++;            
            return 1;

         case pollstate::initial:
            if (0 == strncmp((const char *) pdu->community, community.c_str(), pdu->community_len))
            {
               logger.log_message(LOG_INFO, funcname, "%s: is not responding or having transmission issues.", pdata->hdata->ip);
               pdata->pstate = pollstate::abort;
               return 1;
            }

            logger.log_message(LOG_INFO, funcname, "%s: device is not responding to PDU with preset community. Retrying default.",
                  pdata->hdata->ip);
            pdata->pstate = pollstate::retry;
            return 1;

         case pollstate::retry_initial:
            logger.log_message(LOG_INFO, funcname, "%s: is not responding or having transmission issues.", pdata->hdata->ip);
            pdata->pstate = pollstate::abort;
            return 1;

         default: logger.error_exit(funcname, "%s: unexpected pollstate: %d", pdata->hdata->ip, static_cast<int>(pdata->pstate));            
      }
   }

   return 1;
}

void snmp_init_device(polldata &it)
{
   static const char *funcname {"snmp_init_device"};
   static const oid sys_objid[] { 1, 3, 6, 1, 2, 1, 1, 2, 0 };
   static const conf::string_t &community {config["snmp"]["community"].get<conf::string_t>()};
   static const conf::integer_t timeout {config["snmp"]["timeout"].get<conf::integer_t>()};

   snmp_session snmp_sess;
   snmp_sess_init(&snmp_sess);

   snmp_sess.version = SNMP_VERSION_2c;
   snmp_sess.peername = it.hdata->ip;
   snmp_sess.callback = snmp_pdu_callback;
   snmp_sess.callback_magic = &it;
   snmp_sess.timeout = timeout;

   if (pollstate::initial == it.pstate)
   {
      snmp_sess.community = (u_char *) it.hdata->community;
      snmp_sess.community_len = strlen(it.hdata->community);
   }

   else
   {
      snmp_sess.community = (u_char *) community.c_str();
      snmp_sess.community_len = community.size();
   }

   int liberr, syserr;
   char *errstr;

   if (nullptr == (it.sess = snmp_open(&snmp_sess)))
   {
      snmp_error(&snmp_sess, &liberr, &syserr, &errstr);
      logger.error_exit(funcname, "%s: snmp_open() failed: %s", it.hdata->ip, errstr);
   }

   netsnmp_pdu *req = snmp_pdu_create(SNMP_MSG_GET);
   snmp_add_null_var(req, sys_objid, sizeof(sys_objid) / sizeof(oid));

   if (0 == snmp_send(it.sess, req))
   {
      snmp_error(&snmp_sess, &liberr, &syserr, &errstr);
      logger.error_exit(funcname, "%s: snmp_send() failed: %s", it.hdata->ip, errstr);
   }   
}

void poller(syncdata *sdata)
{
   static const char *funcname {"poller"};
   const unsigned max_hosts = config["snmp"]["max-hosts"].get<conf::integer_t>();
   unsigned active_hosts = 0;

   int fds, block;
   fd_set fdset;
   timeval timeout;

   std::list<polldata> pdata;

   for (;;)
   {
      if (active_hosts < max_hosts)
      {
         std::lock_guard<boost::interprocess::interprocess_mutex> lock {sdata->mlock};
         if (0 == active_hosts and 0 == sdata->dataptr->ip[0]) return;

         unsigned delta = max_hosts - active_hosts;
         for (unsigned i = 0; 0 != sdata->dataptr->ip[0] and i < delta; i++, sdata->dataptr++)
         {
            pdata.emplace_back(sdata->dataptr);
            snmp_init_device(pdata.back());
            active_hosts++;
         }
      }

      fds = block = 0;
      FD_ZERO(&fdset);
      snmp_select_info(&fds, &fdset, &timeout, &block);

      if (0 > (fds = select(fds, &fdset, nullptr, nullptr, &timeout)))
         logger.error_exit(funcname, "select() failed: %s", strerror(errno));
      if (fds) snmp_read(&fdset);
      else snmp_timeout();

      for (auto &p : pdata)
      {
         switch (p.pstate)
         {
            case pollstate::abort:
               pollstat.aborted_devices++;
               pollstat.total_devices++;
               snmp_close(p.sess);
               active_hosts--;
               break;

            case pollstate::finished:
               pollstat.total_devices++;
               snmp_close(p.sess);
               active_hosts--;
               print_mac_file(*sdata, p);
               break;

            case pollstate::retry:
               snmp_close(p.sess);
               snmp_init_device(p);
               p.pstate = pollstate::retry_initial;

            case pollstate::initial: 
            case pollstate::retry_initial:
            case pollstate::polling_iftype: 
            case pollstate::polling_ifname:
            case pollstate::polling_macs:
               break;
         }
      }

      pdata.remove_if([](const polldata &p) { return (pollstate::finished == p.pstate or pollstate::abort == p.pstate); });
   }
}

int main(void)
{
   openlog(progname, LOG_PID, LOG_LOCAL7);
   if (0 == conf::read_config(conffile, config))
      logger.error_exit(progname, "Errors in the configuration file.");

   void *addr = mmap(nullptr, sizeof(syncdata), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (MAP_FAILED == addr) logger.error_exit(progname, "syncdata mmap() failed: %s", strerror(errno));
   syncdata *sdata = new(addr) syncdata;

   prepare_outdir(sdata);
   prepare_data(sdata);

   pid_t fpid = 0;
   for (unsigned i = 0, max = config["pollers"].get<conf::integer_t>() - 1; i < max; i++)
   {
      if (0 > (fpid = fork())) logger.error_exit(progname, "Process fork failed(%u): %s", i, strerror(errno));
      if (0 == fpid) break;      
   }

   init_snmp(progname);
   netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, NETSNMP_OID_OUTPUT_NUMERIC);

   using std::chrono::steady_clock;
   steady_clock::time_point start = steady_clock::now();
   poller(sdata);

   std::chrono::duration<double> elapsed = steady_clock::now() - start;
   logger.log_message(LOG_INFO, progname, 
         "STAT: Total devices: %lu; Aborted Devices: %lu; Interrupted devices: %lu; Total macs: %lu; Written macs: %lu; Time: %f",
         pollstat.total_devices, pollstat.aborted_devices, pollstat.interr_devices,
         pollstat.recv_mac_count, pollstat.save_mac_count, elapsed.count());
   return 0;
}

