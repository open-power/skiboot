#Number of times to sleep
BOOT_TIMEOUT="5";

#Path to memboot binary
#MEMBOOT=${MEMBOOT:-memboot};

#Username/password for ssh to BMC machines
SSHUSER=${SSHUSER:-sysadmin};
export SSHPASS=${SSHPASS:-superuser};

#Username/password for IPMI
IPMI_AUTH="-U ${IPMI_USER:-admin} -P ${IPMI_PASS:-admin}"

# Strip control characters from IPMI before grepping?
STRIP_CONTROL=0

# How do we SSH/SCP in?
SSHCMD="sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $target";
REMOTECPCMD="eval rsync -e \"sshpass -e ssh -l $SSHUSER -o LogLevel=quiet -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no  \" ";

function is_off {
    return $([ "$($IPMI_COMMAND chassis power status)" = "Chassis Power is off" ]);
}

function poweroff {
    $IPMI_COMMAND chassis power off
    # give it some time
    sleep 10
}

function flash {
	$REMOTECPCMD $PNOR $target:/tmp/image.pnor;
	if [ "$?" -ne "0" ] ; then
		error "Couldn't copy firmware image";
	fi

	# Habenaro doesn't have md5sum
	#flash_md5=$(md5sum "$1" | cut -f 1 -d ' ');
	#$SSHCMD "flash_md5r=\$(md5sum /tmp/image.pnor | cut -f 1 -d ' ');
	#	if [ \"$flash_md5\" != \"\$flash_md5r\" ] ; then
	#		exit 1;
	#	fi";
	#if [ "$?" -ne "0" ] ; then
	#	error "Firmware MD5s don't match";
	#fi

	# flash it
	msg "Flashing PNOR"
	$SSHCMD "/usr/local/bin/pflash -E -f -p /tmp/image.pnor"
	if [ "$?" -ne "0" ] ; then
		error "An unexpected pflash error has occured";
	fi
}

function boot_firmware {
    	$IPMI_COMMAND chassis power on > /dev/null;
	i=0;
	while [ "$($IPMI_COMMAND chassis power status)" = "Chassis Power is off" -a \( "$i" -lt "$BOOT_TIMEOUT" \) ] ; do
		msg -n ".";
		sleep $BOOT_SLEEP_PERIOD;
		i=$(expr $i + 1);
	done
	if [ "$i" -eq "$BOOT_TIMEOUT" ] ; then
		error "Couldn't power on $target";
	fi
}

function machine_sanity_test {
    # No further sanity tests for BMC machines.
    true
}
