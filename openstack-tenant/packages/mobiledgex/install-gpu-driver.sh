#!/bin/bash
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# must be run as root

[[ "$TRACE" == yes ]] && set -x

USAGE="usage: $( basename $0 ) <options>

 -n <driver-name>		GPU driver name
 -d <driver-path>		GPU driver path
 -l <license-config-path>	GPU driver license config path

 -h				Display this help message
"
while getopts ":hn:d:l:t:" OPT; do
        case "$OPT" in
        h) echo "$USAGE"; exit 0 ;;
        n) DRIVERNAME="$OPTARG" ;;
        d) DRIVERPATH="$OPTARG" ;;
        l) LICENSECFGPATH="$OPTARG" ;;
        esac
done
shift $(( OPTIND - 1 ))

die() {
        echo "ERROR: $*" >&2
        exit 2
}

TypePassthrough="GpuTypePassthrough"
TypeVGPU="GpuTypeVgpu"

[[ -z $DRIVERNAME ]] && die "Missing GPU driver name"
[[ -z $DRIVERPATH ]] && die "Missing GPU driver path"

if [[ ! -f $DRIVERPATH ]]; then
	die "GPU driver package file '$DRIVERPATH' does not exist"
fi

if [[ ! -z $LICENSECFGPATH ]] && [[ ! -f $LICENSECFGPATH ]]; then
	die "GPU driver license file '$LICENSECFGPATH' does not exist"
fi

PKGNAME=$(dpkg -f $DRIVERPATH package)
PKGVERS=$(dpkg -f $DRIVERPATH version)
if [[ $? -ne 0 ]]; then
	die "Invalid driver package file '$DRIVERPATH', failed to extract package/version details"
fi

curPkgName=$(dpkg-query --showformat='${Package}' --show $PKGNAME)
curPkgVers=$(dpkg-query --showformat='${Version}' --show $PKGNAME)
if [[ $? -eq 0 ]] && [[ $curPkgName == $PKGNAME ]] && [[ $curPkgVerrs == $PKGVERS ]]; then
	echo ">> Skip installing GPU driver, as package '$PKGNAME' of version '$PKGVERS' already exists"
	exit 0
fi

echo ">> Installing GPU driver $DRIVERPATH..."
dpkg -i $DRIVERPATH
[[ $? -ne 0 ]] && die "Failed to install $DRIVERPATH package"
echo ""

# Rebuild ldcache, as installation of deb pkg doesn't perform this
# and hence nvidia-docker doesn't mount all the required modules
echo ">> Rebuilding ldcache..."
ldconfig
[[ $? -ne 0 ]] && die "Failed to rebuild ldcache"
echo ""

if [[ ! -z $LICENSECFGPATH ]]; then
	# License configuration for nvidia-gridd service
	systemctl cat nvidia-gridd.service > /dev/null
	if [[ $? -eq 0 ]]; then
		# Remove init.d file as it causes problems when we enable the service via systemctl
		# nvidia-gridd.service file already exists, hence this is not required
		if [[ -f /etc/init.d/nvidia-gridd ]]; then
			rm /etc/init.d/nvidia-gridd
		fi

		echo ">> Setup GPU driver license config $LICENSECFGPATH for nvidia-gridd..."
		echo ""
		cp $LICENSECFGPATH /etc/nvidia/gridd.conf
		systemctl is-active nvidia-gridd.service > /dev/null
		if [[ $? -ne 0 ]]; then
			systemctl start nvidia-gridd
			[[ $? -ne 0 ]] && die "Failed to start nvidia-gridd service"
		else
			systemctl restart nvidia-gridd
			[[ $? -ne 0 ]] && die "Failed to restart nvidia-gridd service"
		fi

		systemctl enable nvidia-gridd
		[[ $? -ne 0 ]] && die "Failed to enable nvidia-gridd service"

		echo ">> Verifying if GPU driver license is acquired..."
		TIMEOUT=$((SECONDS+300))
		while true; do
			# retry until timeout
			if [ $SECONDS -gt $TIMEOUT ] ; then
				die "Timed out waiting for nvidia-gridd service to acquire license"
			fi
			systemctl is-active nvidia-gridd.service > /dev/null
			if [[ $? -ne 0 ]]; then
				# retry
				echo ">> Waiting for nvidia-gridd service to start - now $SECONDS, timeout $TIMEOUT"
				sleep 5
				continue
			fi
			echo ">> Waiting for license to be acquired - now $SECONDS, timeout $TIMEOUT"
			sleep 5
			systemctl status nvidia-gridd | grep -i "license.*success"
			break
		done
		echo ">> GPU driver license acquired"
	else
		echo ">> Skip license configuration as there is no valid GPU service available..."
	fi
	echo ""
fi

echo ">> Verify GPU driver $DRIVERPATH is installed..."
nvidia-smi -L
[[ $? -ne 0 ]] && die "Failed to verify if $DRIVERPATH package is installed"
echo ""

echo ">> Done setting up GPU driver $DRIVERNAME"
