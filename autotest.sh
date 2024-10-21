#!/usr/bin/env bash

if [ "$1" = "-u" ]
then
  while true; do
    inotifywait -r -e modify,move,create,delete app/ src/ && stack test
  done
else
  while true; do
    inotifywait -r -e modify,move,create,delete app/ src/ test/ && stack test
  done
fi
