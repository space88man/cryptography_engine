#! /bin/bash
set -e -x
# creates a SoftHSMv2 token in tmp/tokens in case
# your local version of softhsm2 is not binary compatible with
# SoftHSM2 v2.3

export SOFTHSM2_CONF=tests/softhsm2.conf
SOFTHSM2_SO=/usr/lib64/libsofthsm2.so

# hardcoded values used by tests/
MY_USER_PIN=userpin
MY_SO_PIN=sopin
MY_LABEL=MyToken1

mkdir -p tmp/tokens

rm -rf tmp/tokens/*

softhsm2-util --init-token --slot 0 --label ${MY_LABEL} --pin ${MY_USER_PIN} --so-pin ${MY_SO_PIN}

SLOTID=$(pkcs11-tool --module ${SOFTHSM2_SO}  -L | grep 'Slot 0' | sed 's/.*ID //')

pkcs11-tool --module ${SOFTHSM2_SO} --slot ${SLOTID} --login --pin userpin \
	    -k --key-type RSA:2048 -a RSA-0001 -d 0001
pkcs11-tool --module ${SOFTHSM2_SO} --slot ${SLOTID} --login --pin userpin \
	    -k --key-type EC:secp384r1 -a EC-0003 -d 0003
	    
