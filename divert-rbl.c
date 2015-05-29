#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

#define DIVERT_PORT 2525

struct hostent* lookup_rbl(in_addr_t n_ip, char* domain){
  char lookup[MAXHOSTNAMELEN];
  char rev_src[INET_ADDRSTRLEN];
  int ret;
  in_addr_t rev = ((n_ip & 0xff000000) >> 24 | 
                   (n_ip & 0x00ff0000) >> 8  |
                   (n_ip & 0x0000ff00) << 8  |
                   (n_ip & 0x000000ff) << 24);

  if(inet_ntop(AF_INET, &rev, rev_src, sizeof(rev_src)) == NULL){
    warn("inet_ntop failed in lookup_rbl");
    return NULL;
  }

  ret = snprintf(lookup, sizeof(lookup), "%s.%s", rev_src, domain);
  if(ret == -1){
    warn("snprintf failed in lookup_rbl");
    return NULL;
  } else if(ret > sizeof(lookup)){
    warn("snprintf overflow in lookup_rbl");
    return NULL;
  }
  
  printf("Looking up %s\n", lookup);
  return gethostbyname(lookup);
}

int pf_add_to_table(struct in_addr n_ip, char* table){

  struct pfioc_table io;
  struct pfr_addr pf_addr;
  struct pfr_table pf_table;
  int pf_fd;
  char* pf_dev = "/dev/pf";
  
  memset(&io, 0, sizeof(io));
  memset(&pf_addr, 0, sizeof(pf_addr));
  memset(&pf_table, 0, sizeof(pf_table));

  //pf_addr.pfra_u._pfra_ip4addr = n_ip;
  pf_addr.pfra_ip4addr = n_ip;
  pf_addr.pfra_af = AF_INET;
  pf_addr.pfra_net = 32;

  if(strlcpy(pf_table.pfrt_name, table, sizeof(pf_table.pfrt_name)) > sizeof(pf_table.pfrt_name)){
    warn("strlcpy failed in pf_add_to_table");
    return -1;
  }

  io.pfrio_table = pf_table;
  io.pfrio_buffer = &pf_addr;
  io.pfrio_size = 1;
  io.pfrio_esize = sizeof(struct pfr_addr);

  pf_fd = open(pf_dev, O_RDWR);
  if(pf_fd == -1){
    warn("open pf_dev failed in pf_add_to_table");
    return -1;
  }
  if(ioctl(pf_fd, DIOCRADDADDRS, &io) == -1){
    warn("ioctl failed in pf_add_to_table");
    close(pf_fd);
    return -1;
  }
  if(close(pf_fd) == -1){
    warn("Close failed in pf_add_to_table");
    return -1;
  }
  /* io.pfrio_nadd should == 1 if successful */
  return io.pfrio_nadd;
}

int
main(int argc, char *argv[])
{
  int fd, s;
  struct sockaddr_in sin;
  socklen_t sin_len;
  struct hostent* host;

  fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
  if (fd == -1){
    err(1, "socket");
  }

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(DIVERT_PORT);
  sin.sin_addr.s_addr = 0;

  sin_len = sizeof(struct sockaddr_in);

  s = bind(fd, (struct sockaddr *) &sin, sin_len);
  if (s == -1){
    err(1, "bind");
  }

  for (;;) {
    ssize_t n;
    char packet[IP_MAXPACKET];
    char src[INET_ADDRSTRLEN + 1];
    //char dst[INET_ADDRSTRLEN + 1];
    struct ip *ip;
    int nadd;

    memset(packet, 0, sizeof(packet));
    memset(src, 0, sizeof(src));
    //memset(dst, 0, sizeof(dst));

    n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *) &sin, &sin_len);
    if (n == -1) {
      warn("recvfrom");
      continue;
    }
    if (n < sizeof(struct ip)) {
      warnx("packet is too short");
      continue;
    }

    ip = (struct ip *) packet;

    if (inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src)) == NULL){
      warn("inet_ntop failed");
      continue;
    }
    printf("src: %s\n", src);
    
    //inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    //printf("src: %s  dst: %s (len: %u)\n", src, dst, ip->ip_len);

    host = lookup_rbl(ip->ip_src.s_addr, "zen.spamhaus.org");
    if(host){
      printf("Host %s resolved\n", src);
    } else {
      printf("Host %s did not resolve\n", src);
    }
    nadd = pf_add_to_table(ip->ip_src, "test");
    printf("Added %d addresses to table %s\n", nadd, "test");

    n = sendto(fd, packet, n, 0, (struct sockaddr *) &sin, sin_len);
    if (n == -1){
      warn("sendto");
    }
  }

  return 0;
}
