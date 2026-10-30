// client5 <port> <delay_ms> <n> <bind_ns>: (prints age of the listener at first connect) sleep, then n sequential connects; prints a result string (. ok, X EPERM, ? other).
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
  int port = atoi(argv[1]), n = atoi(argv[3]);
  struct sockaddr_in a = {.sin_len = sizeof a, .sin_family = AF_INET, .sin_port = htons(port)};
  inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  usleep(atoi(argv[2]) * 1000);
  struct timespec t; clock_gettime(CLOCK_REALTIME, &t);
  long long age_ms = (t.tv_sec * 1000000000LL + t.tv_nsec - atoll(argv[4])) / 1000000;
  char r[256] = "";
  int bad = 0;
  for (int i = 0; i < n && i < 255; i++) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int e = connect(s, (struct sockaddr *)&a, sizeof a) ? errno : 0;
    close(s);
    r[i] = e == 0 ? '.' : e == EPERM ? 'X' : '?';
    bad += e != 0;
  }
  printf("%s age_ms=%lld\n", r, age_ms);
  return bad != 0;
}
