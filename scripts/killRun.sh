#!/bin/env bash
kill -9 `pgrep nuuanu-exe`
stack exec nuuanu-exe &
sleep 0.6
echo -e "server running with PID={`pgrep nuuanu-exe`} (if that's empty, then the server is not running)"
