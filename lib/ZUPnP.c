#include <internal.h>

#ifdef HAVE_UPNP
#include <arpa/inet.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

static struct UPNPUrls __UPnP_urls = {.controlURL = NULL};
static struct IGDdatas __UPnP_data;
static int __UPnP_attempted = 0;
static char* __UPnP_name = "Zephyr Client";

void Z_InitUPnP_ZHM() {
  struct UPNPDev * devlist;
  int upnperror = 0;
  if (__UPnP_active) {
    // tried to initialize twice
    return;
  }
  devlist = upnpDiscover(
			 2000,
			 NULL/*multicast interface*/,
			 NULL/*minissdpd socket path*/,
			 UPNP_LOCAL_PORT_ANY/*sameport*/,
			 0/*ipv6*/,
			 2/*TTL*/,
			 &upnperror);
  if (devlist) {
    int igdfound = UPNP_GetValidIGD(devlist, &__UPnP_urls, &__UPnP_data, NULL, 0);
    if (igdfound) {
      __UPnP_rooturl = __UPnP_urls.rootdescURL;
      char extIpAddr[16];
      if (UPNP_GetExternalIPAddress(__UPnP_urls.controlURL, __UPnP_data.first.servicetype, extIpAddr) == 0) {
	struct in_addr ext_addr;
	if (inet_aton(extIpAddr, &ext_addr)) {
	  __My_addr = ext_addr;
	  __UPnP_active = 1;
	}
      }
    }
    freeUPNPDevlist(devlist);
  }
  __UPnP_name = "Zephyr Host Manager";
  Z_InitUPnP();
}

void Z_InitUPnP() {
  if (__UPnP_attempted) {
    return;
  }
  __UPnP_attempted = 1;
  if (__UPnP_rooturl && !__UPnP_active) {
    __UPnP_active = UPNP_GetIGDFromUrl(__UPnP_rooturl, &__UPnP_urls, &__UPnP_data, NULL, 0);
  }
  if (__UPnP_active) {
    char port_str[16];
    snprintf(port_str, 16, "%d", ntohs(__Zephyr_port));
    int ret = UPNP_AddPortMapping(__UPnP_urls.controlURL,
				  __UPnP_data.first.servicetype,
				  port_str,
				  port_str,
				  inet_ntoa(__My_addr_internal),
				  __UPnP_name, "UDP", NULL, NULL);
    // TODO: Handle error 718 (ConflictInMappingEntry) by choosing a new random port.
  }
}

void Z_CloseUPnP() {
  if (__UPnP_active && __UPnP_attempted) {
    __UPnP_attempted = 0;
    char port_str[16];
    snprintf(port_str, 16, "%d", ntohs(__Zephyr_port));
    UPNP_DeletePortMapping(__UPnP_urls.controlURL,
			   __UPnP_data.first.servicetype,
			   port_str,
			   "UDP",
			   NULL);
  }
}
#else
// Noop.
void Z_InitUPnP_ZHM() {};
void Z_InitUPnP() {}
void Z_CloseUPnP() {}
#endif
