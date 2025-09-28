#!/bin/bash

touch test-files/tv-empty

for r in zero random
do 
    for n in 16 32 256 512 1024
    do
        dd if=/dev/$r of=test-files/tv-$r-$n count=$n > /dev/null 2> /dev/null
    done
done

mkdir -p answers

for alg in sha1 sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224 sha3-256 sha3-384 sha3-512
do
    openssl $alg -r test-files/* > answers/$(echo "$alg" | sed "s/-/_/g")
done

for len in 32 64 128 192 256
do
    for xofalg in shake128 shake256
    do
        openssl $xofalg -xoflen +$len -r test-files/* > answers/${xofalg}_${len}
    done
done