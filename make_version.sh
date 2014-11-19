#!/bin/bash

if test -d .git;
then
	version=`git describe --exact-match 2>/dev/null`
	if [ -z "$version" ];
	then
		version=`git describe 2>/dev/null`
	fi
	if [ -z "$version" ];
	then
		version=`git rev-parse --verify --short HEAD 2>/dev/null`
	fi
	if [ ! -z "$EXTRA_VERSION" ];
	then
		version="$version-$EXTRA_VERSION"
	fi
	if git diff-index --name-only HEAD |grep -qv '.git';
	then
		if [ ! -z "$USER" ];
		then
			version="$version-$USER"
		fi
		version="$version-dirty"
		diffsha=`git diff|sha1sum`
		diffsha=`cut -c-7 <<< "$diffsha"`
		version="$version-$diffsha"
	fi

	echo $version
else
	if [ ! -z "$SKIBOOT_VERSION" ];
	then
		echo $SKIBOOT_VERSION
	else
		exit 1;
	fi
fi
