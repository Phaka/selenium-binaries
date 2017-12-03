@echo off
selenium stop
git pull origin
git clean -x -f
selenium start