// client4 <port> <seconds>: tight loop of connects to 127.0.0.1:port; prints counts and ns timestamps (CLOCK_REALTIME) of non-ok results.
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
static long long now(void) { struct timespec t; clock_gettime(CLOCK_REALTIME, &t); return t.tv_sec * 1000000000LL + t.tv_nsec; }
int main(int argc, char **argv) {
  int port = atoi(argv[1]);
  long long start = now(), end = start + atoll(argv[2]) * 1000000000LL;
  long n = 0, bad = 0;
  struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(port)};
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  printf("start %lld\n", start);
  while (now() < end) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int e = connect(s, (struct sockaddr *)&a, sizeof a) ? errno : 0;
    close(s);
    n++;
    if (e) { bad++; if (bad <= 20) printf("fail %lld %s\n", now(), strerror(e)); }
  }
  printf("total %ld bad %ld\n", n, bad);
  return 0;
}
