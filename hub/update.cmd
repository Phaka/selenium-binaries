@echo off
selenium stop
selenium uninstall
git pull origin
git clean -x -f
selenium install
selenium start