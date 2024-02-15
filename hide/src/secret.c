#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv) {
  if(argc < 2) {
    printf("You don't know how to call %s\n", argv[0]);
    exit(0);
  }

  printf("Hello %s, your secret message is TUNNEL\n", argv[1]);
  exit(0);
}
