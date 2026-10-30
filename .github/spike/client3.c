// client3 <P> <O> <rounds> <host-for-O>: rounds x (connect P; connect O). Prints P-result string (. ok, X EPERM, ? other) and O string.
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static int conn(const char *ip, int port) {
  struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(port)};
  inet_pton(AF_INET, ip, &a.sin_addr);
  int s = socket(AF_INET, SOCK_STREAM, 0);
  int e = connect(s, (struct sockaddr *)&a, sizeof a) ? errno : 0;
  close(s);
  return e;
}
int main(int argc, char **argv) {
  int P = atoi(argv[1]), O = atoi(argv[2]), n = atoi(argv[3]);
  char ps[4096] = "", os[4096] = "";
  int bad = 0;
  for (int i = 0; i < n && i < 4000; i++) {
    int e = conn("127.0.0.1", P);
    ps[i] = e == 0 ? '.' : e == EPERM ? 'X' : '?'; bad += e != 0;
    if (O) { e = conn(argv[4], O); os[i] = e == 0 ? '.' : e == EPERM ? 'X' : '?'; }
  }
  printf("P=%s\nO=%s\n", ps, os);
  return bad != 0;
}
