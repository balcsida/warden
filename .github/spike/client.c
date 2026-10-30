// Spike client: client <mode> <port>...  mode: b = blocking connect, n = nonblocking+poll (like Rust connect_timeout)
// Prints "<port> <ok|errno-name>" per connect, sequentially in one process.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int rc = 0;
  for (int i = 2; i < argc; i++) {
    int port = atoi(argv[i]);
    struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int nb = argv[1][0] == 'n' && i == 2;
    if (nb) fcntl(s, F_SETFL, O_NONBLOCK);
    int r = connect(s, (struct sockaddr *)&a, sizeof a), e = r ? errno : 0;
    if (nb && r && e == EINPROGRESS) {
      struct pollfd p = {s, POLLOUT, 0};
      poll(&p, 1, 2000);
      socklen_t l = sizeof e; getsockopt(s, SOL_SOCKET, SO_ERROR, &e, &l);
    }
    printf("%d %s\n", port, e ? strerror(e) : "ok");
    if (e && i == argc - 1) rc = 1;
    close(s);
  }
  return rc;
}
