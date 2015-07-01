#!/bin/bash

usage() {
	echo "$0 git-tag-prefix"
	echo -e "\tIf inside git dir specify a tag prefix to use."
	echo -e "\tWhere a prefix is anything before the first dash '-' character."
	echo
	if test -d .git || git rev-parse --is-inside-work-tree > /dev/null 2>&1;
	then
		echo "Possible tags include:"
		git tag | cut -d '-' -f 1 | sort | uniq
	fi
}

if test -e .git || git rev-parse --is-inside-work-tree > /dev/null 2>&1;
then
	if [ $# -ne "1" ] ; then
		usage
		exit 1;
	fi

	TAG_PREFIX="$1"

	#Check that there is at least one of such a prefix
	if ! git tag | grep -q "$TAG_PREFIX" ; then
		echo -e "There isn't a single gix tag with prefix '$TAG_PREFIX'\n" > stderr
	fi

	version=`git describe --exact-match --match "$TAG_PREFIX-*" 2>/dev/null`
	if [ -z "$version" ];
	then
		version=`git describe --match "$TAG_PREFIX-*" 2>/dev/null`
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
		if [ ! -z "`cat .version`" ];
		then
			cat .version
		else
			exit 1;
		fi
	fi
fi
