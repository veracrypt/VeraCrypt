#!/bin/sh
V="$(mount | grep veracrypt_aux_mnt)"
if [ ! -z "$V" ]
then
	echo "Error: All VeraCrypt volumes must be dismounted first." 
	exit 1
else
	exit 0
fi 