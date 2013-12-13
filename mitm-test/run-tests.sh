#!/bin/bash -e

# change working directory to the root of the project
cd $(realpath $(dirname $0)/..)

# global variables
version=1.0.0
port=12345
mitm_port=8443
mitm_user=nobody
failed=0

# on failure shut down any remaining children
# TODO also clear up iptables rules?
trap 'sudo kill -9 0' SIGINT SIGTERM EXIT

# functions for controlling the MITM server
start_mitm_server() {
  local trust=$1
  local hostname=$2

  pushd mitm >/dev/null
  sudo -u $mitm_user java -jar build/libs/mitm-$version.jar --nat --$trust --$hostname >/dev/null &
  mitm_server_pid=$!
  sleep 1 # wait a bit to ensure the socket has started listening
  popd >/dev/null
}

stop_mitm_server() {
  sudo kill $mitm_server_pid
  wait $mitm_server_pid || true
}

# functions for controlling the test server
start_test_server() {
  pushd mitm-test-server >/dev/null
  java -jar build/libs/mitm-test-server-$version.jar &
  sleep 1 # wait a bit to ensure the socket has started listening
  test_server_pid=$!
  popd >/dev/null
}

stop_test_server() {
  kill $test_server_pid
  wait $test_server_pid || true
}

# functions for adding/removing the iptables rules
start_iptables() {
  sudo iptables -t nat -A OUTPUT -p tcp --dport $port -m owner --uid-owner $mitm_user -j ACCEPT
  sudo iptables -t nat -A OUTPUT -p tcp --dport $port -j REDIRECT --to-port $mitm_port
}

stop_iptables() {
  sudo iptables -t nat -D OUTPUT -p tcp --dport $port -m owner --uid-owner $mitm_user -j ACCEPT
  sudo iptables -t nat -D OUTPUT -p tcp --dport $port -j REDIRECT --to-port $mitm_port
}

# code common to each test case
test_case() {
  local trust=$1
  local hostname=$2
  local expected_result=$3

  pushd mitm-test-client >/dev/null
  set +e
  java -jar build/libs/mitm-test-client-$version.jar --$trust --$hostname 2>/dev/null
  local actual_result=$?
  set -e
  if $expected_result && [ $actual_result -eq 0 ]; then
    echo pass
  elif ! $expected_result && [ $actual_result -ne 0 ]; then
    echo pass
  else
    echo "fail ($trust cert, ${hostname/-/ })"
    failed=1
  fi
  popd >/dev/null
}

# let's go!
start_test_server

# check connection works in all cases without a MITM
echo "MITM - disabled:"
test_case trusted   matching-hostname   true
test_case untrusted matching-hostname   true
test_case trusted   unmatching-hostname true
test_case untrusted unmatching-hostname true

# test cases using trusted certificate with matching hostname
echo "MITM - trusted cert, matching hostname:"
start_iptables
start_mitm_server trusted matching-hostname
test_case trusted   matching-hostname   true
test_case untrusted matching-hostname   true
test_case trusted   unmatching-hostname true
test_case untrusted unmatching-hostname true
stop_mitm_server

# test cases using untrusted certificate with matching hostname
echo "MITM - untrusted cert, matching hostname:"
start_mitm_server untrusted matching-hostname
test_case trusted   matching-hostname   false
test_case untrusted matching-hostname   true
test_case trusted   unmatching-hostname false
test_case untrusted unmatching-hostname true
stop_mitm_server

# test cases using trusted certificate with unmatching hostname
echo "MITM - trusted cert, unmatching hostname"
start_mitm_server trusted unmatching-hostname
test_case trusted   matching-hostname   false
test_case untrusted matching-hostname   false
test_case trusted   unmatching-hostname true
test_case untrusted unmatching-hostname true
stop_mitm_server

# test cases using untrusted certificate with unmatching hostname
echo "MITM - untrusted cert, unmatching hostname:"
start_mitm_server untrusted unmatching-hostname
test_case trusted   matching-hostname   false
test_case untrusted matching-hostname   false
test_case trusted   unmatching-hostname false
test_case untrusted unmatching-hostname true

# stop everything - we're done
stop_iptables
stop_test_server

# print final output and exit
if [ $failed -eq 0 ]; then
  echo "*** SUCCESS ***"
else
  echo "*** FAILURE ***"
fi
exit $failed
