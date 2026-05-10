@echo off
echo Compiling AuthClient...
if not exist bin mkdir bin
javac -d bin src\AuthClient.java
if %errorlevel% == 0 (
    echo Compilation successful!
    echo To run: run.bat [host] [port]
) else (
    echo Compilation failed!
)
