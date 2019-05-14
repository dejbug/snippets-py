@echo off
REM pack the two text files "empty.txt" and "one.txt" in plain text (i.e. uncompressed) into the zip archive "two.zip".
7z a two.zip empty.txt one.txt -mx=0
