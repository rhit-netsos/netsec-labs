#!/bin/bash


# color variables
RED='\033[1;31m'    # red
YELLOW='\033[1;33m' # yellow
GREEN='\033[1;32m'  # green
RESET='\033[0m'     # no color

# Print a warning for the user.
#
# @param First argument is the warning message to print to the user.
#
print_warning() {
  echo -n -e "$YELLOW"
  echo -e "[WARNING] $1"
  echo -n -e "$RESET"
}

# Print an error message for the user
#
# @param First argument is the error message to print to the user.
#
print_error() {
  echo -n -e "$RED"
  echo -e "[ERROR] $1"
  echo -n -e "$RESET"
}

# Print a log for the user.
#
# @param First argument is the log message to print to the user.
#
print_log() {
  echo -n -e "$GREEN"
  echo -e "$1"
  echo -n -e "$RESET"
}

# Print the usage description for this program, usually program exits after
# this.
#
print_usage() {
  echo -e "usage: $0 <SUBNET>"
}

# Patch the docker-compose file with each username, otherwise networks will not
# be created.

LAB=lab2
STUDENT=$(whoami)
SUBNET=$1

if [ -z $SUBNET ]; then
  print_log "Attempting to fetch subnet automatically..."
  wget -q -O subnets.csv https://rosehulman-my.sharepoint.com/:x:/g/personal/noureddi_rose-hulman_edu/EdBKHIsxC-hFp6BGXPZ8pgQBIivgZ9BUW6YKVdSQl9wQaA\?download\=1
  SUBNET=$(grep -e $STUDENT subnets.csv | cut -d',' -f 4)
  if [ -z $SUBNET ]; then
    rm -f subnets.csv || true
    print_error "Could not fetch your subnet, please add it manually."
    echo -e ""
    print_usage
    exit 99
  fi
  print_log "Found your subnet, it is $SUBNET"
  rm -f subnets.csv || true
fi

# check if already patched!
if [ "$(grep -i -c -e "$STUDENT" docker-compose.yml)" -gt 0 ]; then
  print_error "########################################################################"
  print_error "# It looks like your docker-compose.yml file has already been patched. #"
  print_error "#                                                                      #"
  print_error "# If you are having issues bringing up the environment, it means it is #"
  print_error "#  still in use.                                                       #"
  print_error "#                                                                      #"
  print_error "# Try to take down the experiment first, then bring it up again.       #"
  print_error "#  To bring it down: docker compose down                               #"
  print_error "#  To bring it up:   docker compose up -d                              #"
  print_error "########################################################################"
  exit 99
fi


# patch hosts
PATTERN="s/\(host[A-Z]\)/${STUDENT}-\1/g"
sed -i $PATTERN docker-compose.yml

# patch attacker
PATTERN="s/attacker/${STUDENT}-attacker/g"
sed -i $PATTERN docker-compose.yml

# patch network
PATTERN="s/local-net/${STUDENT}-local-net/g"
sed -i $PATTERN docker-compose.yml

# patch network subnet
PATTERN="s/10.10.0/${SUBNET}/g"
sed -i $PATTERN docker-compose.yml

# generate connection scripts
print_log "Generating connection scripts..."
HOSTS="hostA hostB attacker"
for hhost in ${HOSTS}
do
  cat > connect_$hhost.sh << EOF
#!/bin/bash
docker container exec -it ${STUDENT}-${hhost} /bin/bash
EOF
done

# fix permissions
chmod +x *.sh

print_log "Done..."

