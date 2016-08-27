/* te.c - Small utilty to show network stats.
*     
* Copyright (c) 2016 by Hypsurus <hypsurus@mail.ru>   
*
* te is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 3 of the License, or
* (at your option) any later version.
*
* te is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <features.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <getopt.h>

#define VERSION "0.1-dev"
#define MAX_STR 256
#define MAX_ARP_CACHE 1024

#define PATH_MAC_PREFIXES "/usr/local/share/te/mac-prefixes"
#define PATH_PROC_NET_ARP "/proc/net/arp"


/* Colors */
#define NRM  "\x1B[0m"
#define RED  "\x1B[31m"
#define GRN  "\x1B[32m"
#define YEL  "\x1B[33m"
#define BLU  "\x1B[34m"
#define MAG  "\x1B[35m"
#define CYN  "\x1B[36m"
#define WHT  "\x1B[37m"
#define END "\033[0m"

/* Unicode */
#define UNICODE_LINE  "\xe2\x94\x80"
#define UNICODE_CHECK "\xe2\x9c\x93"
#define UNICODE_X   "x"

enum {IP_ADDR, HW_TYPE, FLAGS, MAC_ADDR, MASK, DEV};
enum {ERROR, INFO};
enum {FALSE, TRUE};

typedef struct {
  char *ip;
  char hwaddr[MAX_STR];
  FILE *hwaddr_fp;
  struct sockaddr_in *s;
  struct ifaddrs *addrs;
} ifconfig_t;

typedef struct {
  int flag; /* The command line argument flag. */
} te_t;


/* Print message by type */
void msg(int type, int quit, char *format, ...) {
  va_list li;
  char msg[MAX_STR];

  va_start(li, format);
  vsprintf(msg, format, li);
  va_end(li);

  switch(type) {
    case ERROR:
      printf("%s%s%s %s%s%s", RED, UNICODE_X, END,
        WHT, msg, END);
      break;
  }

  if ( quit ) exit(0);
}

/* Return formetted string from a function */
char *xformate_return(char *format, ...) {
  char *buffer = NULL;
  va_list li;

  va_start(li, format);
  vasprintf(&buffer, format, li);
  va_end(li);

  return buffer;
}

/* Print char n times. (ch * n) */
void unicode_putchar(char *ch, size_t n) {
  int i = 0;

  for(i = 0;i <= n;i++) {
    printf("%s", ch);
  }
  putchar(0x0a);
}

/* Xalloacte */
void *te_xalloc(size_t size) {
  void *p = calloc(size, 1);

  if (!p) exit(0);
  return p;
}

/* Detect hw address */
char *te_hwaddr_detect(char *hwaddr) {
  FILE *fp = NULL;
  char prefix[MAX_STR], vendor[MAX_STR];
  char buffer[MAX_STR], nhwaddr[MAX_STR];

  /* Fix the prefix to upper case A1B2C3 */
  sprintf(nhwaddr, "%c%c%c%c%c%c", toupper(hwaddr[0]), 
    toupper(hwaddr[1]),
    toupper(hwaddr[3]), toupper(hwaddr[4]),
    toupper(hwaddr[6]), toupper(hwaddr[7]));

  if (( fp = fopen(PATH_MAC_PREFIXES, "r")) == NULL ) {
    msg(ERROR, TRUE, "Cannot open: %s\n", PATH_MAC_PREFIXES);
  }

  while((fgets(buffer, sizeof(buffer), fp)) != NULL ) {
    sscanf(buffer, "%s %[^\n]s", prefix, vendor);
    if ( strcmp(prefix, nhwaddr) == 0 ) {
      strtok(nhwaddr, "\n");
      return xformate_return(vendor);
      break;
    }
  }

  fclose(fp);
  
  return NULL;
}

/* free() **xptr[i] when done. */
void te_arp_table_get(int col, FILE *table, char **xptr) {
  char **ptr = xptr;
  char line[MAX_STR];

  if (( table = fopen(PATH_PROC_NET_ARP, "r")) == NULL ) {
    msg(ERROR, TRUE, "Cannot open: %s\n", PATH_PROC_NET_ARP);
  }
    
  while (( fgets(line, sizeof(line), table)) != NULL ) {
    if ( isdigit(line[0] )) {
      *ptr = te_xalloc(18); /* Mac address size+1*/
      switch(col) {
        case IP_ADDR:
          sscanf(line, "%s", *ptr);
          break;
        case HW_TYPE: 
          sscanf(line, "%*s %s", *ptr);
          break;
        case FLAGS:
          sscanf(line, "%*s %*s %s", *ptr);
          break;
        case MAC_ADDR:
          sscanf(line, "%*s %*s %*s %s", *ptr);
          break;
        case MASK:
          sscanf(line, "%*s %*s %*s %*s %s", *ptr);
          break;
        case DEV:
          sscanf(line, "%*s %*s %*s %*s %*s %s", *ptr);
          break;
      }
      ptr++;
    }
  }

  fclose(table);
}

void te_arp_table(te_t *t) {
  FILE *table = NULL;
  int i = 0;
  int line_size = 73;
  char *ip[MAX_ARP_CACHE];
  char *hw_type[MAX_ARP_CACHE];
  char *flags[MAX_ARP_CACHE];
  char *mac_addr[MAX_ARP_CACHE];
  char *mask[MAX_ARP_CACHE];
  char *dev[MAX_ARP_CACHE];
  char *mac_vendor = NULL;

  te_arp_table_get(IP_ADDR, table, ip);
  te_arp_table_get(HW_TYPE, table, hw_type);
  te_arp_table_get(FLAGS, table, flags);
  te_arp_table_get(MAC_ADDR, table, mac_addr);
  te_arp_table_get(MASK, table, mask);
  te_arp_table_get(DEV, table, dev);

  for ( i = 0; ip[i] != 0; i++ ) {
    mac_vendor = te_hwaddr_detect(mac_addr[i]);
    if ( mac_vendor == NULL )
      mac_vendor = "Unknown";
    else {
      if ( i == 0 )
        line_size += strlen(mac_vendor);
    }

    if ( i == 0 ) {
      printf("  Address \tHWtype \tFlags \tHWAddr \t\t\tMask \tIface \t\tVendor\n");
    }

    /* Incomplete ARP request 0x0 */
    if ( flags[i][2] == '0' ) {
      printf("%s%s%s %s%s%s %s%s%s \t%s%s%s \t%s%s%s \t%s%s%s \t%s \t%s\n", RED, UNICODE_X, END,
        YEL, ip[i],END,
        CYN, hw_type[i],END, 
        MAG, flags[i],END,
        GRN, mac_addr[i],END,
        BLU, mask[i], END, 
        dev[i], 
        mac_vendor ? mac_vendor : "");
    } 
    /* Complete ARP request 0x02 */
    else if ( flags[i][2] == '2' ) {
      printf("%s%s%s %s%s%s \t%s%s%s \t%s%s%s \t%s%s%s \t%s%s%s \t%s \t%s\n", GRN, UNICODE_CHECK, END,
        YEL, ip[i],END,
        CYN, hw_type[i],END, 
        MAG, flags[i],END,
        GRN, mac_addr[i],END,
        BLU, mask[i], END, 
        dev[i], 
        mac_vendor ? mac_vendor : "");  
    }

    free(ip[i]);
    free(hw_type[i]);
    free(flags[i]);
    free(mac_addr[i]);
    free(mask[i]);
    free(dev[i]);
  }
}

/* Show network interfaces stats */
void te_ifconfig(ifconfig_t *ic, te_t *t) {
  char path[MAX_STR];
  char *mac_vendor = NULL;

  getifaddrs(&ic->addrs);
  
  while ( ic->addrs ) {
    ic->s = (struct sockaddr_in *)ic->addrs->ifa_addr;
    ic->ip = inet_ntoa(ic->s->sin_addr);

    if ( ic->addrs->ifa_addr->sa_family == PF_INET ) {
      sprintf(path, "/sys/class/net/%s/address", ic->addrs->ifa_name);
      if (( ic->hwaddr_fp = fopen(path, "r")) == NULL )
        strcat(ic->hwaddr, "00:00:00:00:00:00");
      else
        fscanf(ic->hwaddr_fp, "%s", ic->hwaddr);
    
      mac_vendor = te_hwaddr_detect(ic->hwaddr);
      if ( mac_vendor == NULL )
        mac_vendor = "Unknown";
      printf("%s%s%s %s%s%s: \n  inet: %s%s%s \n  ether: %s%s %s%s\n", GRN,UNICODE_CHECK,END,
      YEL, ic->addrs->ifa_name, END, 
      BLU, ic->ip, END,
      RED, ic->hwaddr, 
      mac_vendor ? mac_vendor : "", 
      END);
    }
    ic->addrs = ic->addrs->ifa_next;  
  }

  freeifaddrs(ic->addrs);
}

void te_printe_version(void) {
  printf("%s//t%s %s%s%s- A small utility to view network stats.\n",YEL,END,
    GRN,VERSION,END);
  printf("%s//Written by @Hypsurus (hypsurus@mail.ru)%s\n", CYN,END);
}

void te_printe_usage(char *file_name) {
  printf("Usage: %s [OPTIONS] ...\n", file_name);
  printf("\nOptions:\n");
  printf("\t-a, --arp      -   Show the ARP table.\n");
  printf("\t-i, --ifconfig   -   Show network interfaces information.\n");
  printf("\t-m, --mac-vendor -   Show MAC address vendor with the output.\n");
  printf("\nCopyright (c) 2016 by Hypsurus <hypsurus@mail.ru>\n");
  printf("Full documentation at: <http://github.com/Hypsurus/te>\n");
  exit(0);
}

int main(int argc, char **argv) {
  ifconfig_t ic;
  te_t t;

  int opt = 0;
  int opte_index = 0;
  static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"arp", no_argument, 0, 'a'},
    {"ifconfig", no_argument, 0, 'i'},
    {"version", no_argument, 0, 'v'},
    {0,0,0,0}
  };

  while (( opt = getopt_long(argc, argv, "haiv", 
    long_opts, &opte_index)) != -1 ) {
    
    switch(opt) {
      case 'a':
        te_arp_table(&t);
        break;
      case 'i':
        te_ifconfig(&ic, &t);
        break;
      case 'v':
        te_printe_version();
        break;
      case 'h':
        te_printe_usage(argv[0]);
      default:
        break;
    }
  }
  
  if ( argc < 2 ) 
    te_ifconfig(&ic, &t);
  
  return 0; 
}
