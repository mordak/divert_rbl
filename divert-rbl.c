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
#include <pwd.h>
#include <syslog.h>
#include <stdarg.h>

#define DIVERT_PORT 2525
#define PF_DEV "/dev/pf"
#define UNPRIVILEGED_USER "nobody"
#define CHROOT_DIR "/var/empty"
#define RBL_DOMAIN "zen.spamhaus.org"

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

  return gethostbyname(lookup);
}

int pf_add_to_table(struct in_addr n_ip, char* table){

  struct pfioc_table io;
  struct pfr_addr pf_addr;
  struct pfr_table pf_table;
  int pf_fd;

  memset(&io, 0, sizeof(io));
  memset(&pf_addr, 0, sizeof(pf_addr));
  memset(&pf_table, 0, sizeof(pf_table));

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

  pf_fd = open(PF_DEV, O_RDWR);
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
  return io.pfrio_nadd;
}

void child_fatal(int exit_val, char* message){
  warn(message);
  _exit(exit_val);
}

int main(int argc, char *argv[]){
  int fd;
  struct sockaddr_in sin;
  socklen_t sin_len;
  int q_pipe[2];
  pid_t cpid;

  /* set up the divert socket */
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
  if (fd == -1)
    err(1, "socket");

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(DIVERT_PORT);
  sin.sin_addr.s_addr = 0;

  sin_len = sizeof(struct sockaddr_in);

  if(bind(fd, (struct sockaddr *) &sin, sin_len) == -1)
    err(1, "bind");

  /* set up the pipe for privsep */
  if(pipe(q_pipe) == -1)
    err(1, "pipe");

  /* now fork and do the work */
  if((cpid = fork())){
    /* parent */
    int num_b;
    struct in_addr new_ip;
    char psync;
    struct hostent* host;

    close(fd);

    for(;;){
      memset(&new_ip, 0, sizeof(struct in_addr));

      num_b = read(q_pipe[0], &new_ip, sizeof(struct in_addr));
      if(num_b == -1)
        err(129, "parent read from q_pipe");
      if(num_b == 0)
        err(130, "parent read EOF from q_pipe");
      host = lookup_rbl(new_ip.s_addr, RBL_DOMAIN);
      if(host){
        psync = 1;
        if(pf_add_to_table(new_ip, "rbl-spammers") == -1)
          warnx("Could not add ip to table rbl-spammers");
      } else {
        psync = 0;
        if(pf_add_to_table(new_ip, "rbl-clean") == -1)
          warnx("Could not add ip to table rbl-clean");
      }

      if(write(q_pipe[0], &psync, 1) == -1)
        err(128, "parent write to q_pipe");
    }
  } else {
    /* child */
    struct passwd *pw;

    /* drop privileges and chroot */
    pw = getpwnam(UNPRIVILEGED_USER);
    if(chroot(CHROOT_DIR) == -1)
      child_fatal(2, "Could not chroot");
    if(chdir("/") == -1)
      child_fatal(3, "Could not chdir to /");
    if(pw == NULL)
      child_fatal(5, "Could not fetch user nobody");
    if (setgroups(1, &pw->pw_gid) ||
        setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
        setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
      child_fatal(4, "Could not drop privileges");

    /* loop forever */
    for (;;) {
      ssize_t n;
      char packet[IP_MAXPACKET];
      char src[INET_ADDRSTRLEN + 1];
      struct ip *ip;
      char sync;
      int num_bc;

      memset(packet, 0, sizeof(packet));
      memset(src, 0, sizeof(src));

      n = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *) &sin, &sin_len);
      if (n == -1) {
        warn("recvfrom");
        continue;
      }
      if (n < sizeof(struct ip)) {
        warnx("packet is too short");
        continue;
      }

      /* pull off the ip header */
      ip = (struct ip *) packet;
      if (inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src)) == NULL){
        warn("inet_ntop failed");
        continue;
      }

      /* send the ip to the parent, which tells us if it's a spammer */
      if(write(q_pipe[1], &ip->ip_src.s_addr, sizeof(struct in_addr)) == -1)
        child_fatal(128, "child write to q_pipe");
      num_bc = read(q_pipe[1], &sync, 1);
      if(num_bc == -1)
        child_fatal(129, "child read from q_pipe");
      if(num_bc == 0)
        child_fatal(130, "child read EOF from q_pipe");
      if(sync){
        syslog(LOG_INFO, "SPAM: %s\n", src);
        /* Drop.. */
      } else {
        syslog(LOG_INFO, "CLEAN: %s", src);
        if(sendto(fd, packet, n, 0, (struct sockaddr *) &sin, sin_len) == -1)
          warn("sendto");
      }
    }
  }
  return 0;
}
