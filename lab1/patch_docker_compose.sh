#!/usr/bin/env bash

# Patch the docker-compose file with each username, otherwise networks will not
# be created.

STUDENT=$1
SUBNET=$2

if [ -z $STUDENT ]; then
  echo "Please enter you student id"
  exit 99
fi

if [ -z $SUBNET ]; then
  echo "Please enter your subnet as the second argument."
  exit 99
fi

# patch hosts
PATTERN="s/\(host[A-Z]\)/${STUDENT}-\1/g"
sed -i $PATTERN docker-compose.yml

# patch attacker
PATTERN="s/attacker/${STUDENT}-attacker/g"
sed -i $PATTERN docker-compose.yml

# patch hostA
# PATTERN="s/hostA/${STUDENT}-hostA/g"
# sed -i $PATTERN docker-compose.yml

# patch hostB
# PATTERN="s/hostB/${STUDENT}-hostB/g"
# sed -i $PATTERN docker-compose.yml

# patch network
PATTERN="s/local-net/${STUDENT}-local-net/g"
sed -i $PATTERN docker-compose.yml

# patch network subnet
PATTERN="s/10.10/${SUBNET}/g"
sed -i $PATTERN docker-compose.yml

echo -e "Done...."

