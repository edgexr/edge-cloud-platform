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


MAIN_ANSIBLE_VAULT_PREFIX='ansible-mex-vault'
PERSONAL_ANSIBLE_VAULT='personal-ansible-vault.yml'
DEFAULT_PLAYBOOK='mexplat.yml'
EC_VERSION=$( date +'%Y-%m-%d' )

USAGE="usage: $0 [options] <environment> [<target>]

  -c		confirm before running playbook
  -C <version>	console version to deploy (default: pick latest git tag)
  -d		enable debug mode
  -D		pick edge-cloud images from the \"mobiledgex-dev\" docker registry
  -e <var=val>	pass environment variables to playbook run
  -G		skip github login
  -i		interactive mode; pause before each region upgrade
  -l		list available targets
  -n		dry-run mode
  -p <playbook>	playbook (default: \"$DEFAULT_PLAYBOOK\")
  -q		quiet mode; skip Slack notifications
  -s <tags>     skip tags (comma-separated)
  -S		step (confirm each step)
  -t <tags>	tags (comma-separated)
  -v            verbose mode; can be repeated to increase verbosity
  -V <version>	edge-cloud version to deploy (default: \"$EC_VERSION\")
  -x            skip vault SSH key signing
  -X <vault>    vault URL
  -y		skip confirmation prompts

  -h		display this help message

example: $0 -n staging console"

# See: https://github.com/ansible/ansible/issues/49207
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES

die() {
	echo "ERROR: $*" >&2
	exit 2
}

: ${ANSIBLE_VENV:=$HOME/venv/ansible}
if [[ ! -d "$ANSIBLE_VENV" ]]; then
	if [[ $$ == 1 ]]; then
		# Running inside a docker container
		true
	else
		echo
		echo "WARNING: Could not find virtualenv"
		echo "         See ansible/README.md for details on setting up the environment"
		echo
	fi
else
	echo "Using virtual environment: $ANSIBLE_VENV"
	. $ANSIBLE_VENV/bin/activate || die "Failed to source virtul environment: $ANSIBLE_VENV"
fi

DRYRUN=false
LIST=false
DEBUG=false
CONFIRM=false
ASSUME_YES=false
PLAYBOOK_FORCED=
TAGS=
SKIP_TAGS=
STEP=false
SKIP_GITHUB=false
INTERACTIVE=false
CONSOLE_VERSION=
EC_VERSION_SET=false
QUIET_MODE=false
SKIP_VAULT_SSH_KEY_SIGNING=false
VAULT_ADDR=
VERBOSITY=
ENVVARS=()
while getopts ':cC:dDe:Ghilnp:qs:St:vV:xX:y' OPT; do
	case "$OPT" in
	c)	CONFIRM=true ;;
	C)	CONSOLE_VERSION="$OPTARG" ;;
	d)	DEBUG=true ;;
	D)	ENVVARS+=( -e "mex_registry_project=mobiledgex-dev"
			   -e "cloudlet_registry_path=harbor.mobiledgex.net/mobiledgex-dev/edge-cloud-crm" ) ;;
	e)	ENVVARS+=( -e "$OPTARG" ) ;;
	G)	SKIP_GITHUB=true ;;
	i)	INTERACTIVE=true ;;
	n)	DRYRUN=true ;;
	l)	LIST=true ;;
	p)	PLAYBOOK_FORCED="$OPTARG" ;;
	q)	QUIET_MODE=true ;;
	s)	SKIP_TAGS="$OPTARG" ;;
	S)	STEP=true ;;
	t)	TAGS="$OPTARG" ;;
	v)	VERBOSITY="${VERBOSITY}v" ;;
	V)	EC_VERSION="$OPTARG"; EC_VERSION_SET=true ;;
	x)	SKIP_VAULT_SSH_KEY_SIGNING=true ;;
	X)	VAUT_ADDR="$OPTARG" ;;
	y)	ASSUME_YES=true ;;
	h)	echo "$USAGE"
		exit 0
		;;
	*)	echo "unknown option or missing argument: $OPTARG" >&2
		echo "$USAGE" >&2
		exit 1
		;;
	esac
done
shift $(( OPTIND - 1 ))

ENVIRON="$1"; shift
TARGET="$1"; shift

if [[ -z "$ENVIRON" ]]; then
	echo "$USAGE" >&2
	exit 1
fi

if [[ ! -e "$ENVIRON" ]]; then
	echo "$ENVIRON: inventory not found" >&2
	exit 2
fi

if [[ -n "$PLAYBOOK_FORCED" && ! -f "$PLAYBOOK_FORCED" ]]; then
	echo "$PLAYBOOK_FORCED: playbook not found" >&2
	exit 2
fi

[[ "$ENVIRON" == main ]] && CONFIRM=true
$EC_VERSION_SET || CONFIRM=true

# List mode
"$LIST" && exec ansible-inventory -i "$ENVIRON" --graph

ARGS=()
$DRYRUN && ARGS+=( '--check' )
$STEP && ARGS+=( '--step' )
[[ -n "$VERBOSITY" ]] && ARGS+=( "-${VERBOSITY}" )

[[ -n "$ANSIBLE_SSH_PRIVATE_KEY_FILE" ]] \
	&& ARGS+=( --private-key "$ANSIBLE_SSH_PRIVATE_KEY_FILE" )

# Add personal ansible vault to command line, if present
if [[ -f "$PERSONAL_ANSIBLE_VAULT" ]]; then
	ARGS+=( -e "@${PERSONAL_ANSIBLE_VAULT}" )
elif [[ -f "${HOME}/${PERSONAL_ANSIBLE_VAULT}" ]]; then
	ARGS+=( -e "@${HOME}/${PERSONAL_ANSIBLE_VAULT}" )
elif [[ "$SKIP_GITHUB" != true && -z "$CONSOLE_VERSION" ]]; then
	if [[ -z "$GITHUB_USER" || -z "$GITHUB_TOKEN" ]]; then
		# Get Github creds from user
		read -p 'Github username: ' GITHUB_USER
		read -p 'Github password/token: ' -s GITHUB_TOKEN
	fi
	curl --fail --user "${GITHUB_USER}:${GITHUB_TOKEN}" https://api.github.com/users/${GITHUB_USER} >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo; echo
		echo "Unable to log in to Github!" >&2
		echo "If you have 2FA enabled, you need a personal access token to log in:" >&2
		echo "   https://help.github.com/en/articles/creating-a-personal-access-token-for-the-command-line" >&2
		exit 2
	fi
	export GITHUB_USER GITHUB_TOKEN
fi

# Figure out vault address
if [[ -z "$VAULT_ADDR" ]]; then
	# Pick vault address from Ansible
	VAULT_ADDR=$( ansible-inventory -i "$ENVIRON" --list --export | jq -r .all.vars.vault_address )
	[[ -z "$VAULT_ADDR" ]] && die "Unable to determine vault instance"
fi

VAULT_SSH_ROLE=user
if [[ -n "$VAULT_TOKEN" ]]; then
	echo "Authenticating using vault token" >&2
elif [[ -n "$VAULT_ROLE_ID" && -n "$VAULT_SECRET_ID" ]]; then
	echo "Authenticating using vault role/secret" >&2
	VAULT_SSH_ROLE=ansible
elif [[ -n "$GITHUB_TOKEN" ]]; then
	echo "Generating vault token using Github auth" >&2
	VAULT_TOKEN=$( VAULT_ADDR="$VAULT_ADDR" \
		vault login -format=json -method=github token="$GITHUB_TOKEN" \
		| jq -r .auth.client_token )
	if [[ -z "$VAULT_TOKEN" ]]; then
		echo; echo
		echo "Failed to log in to vault using Github token!" >&2
		exit 2
	fi
else
	echo "Vault role/secret not provided; falling back to token auth" >&2
	while [[ -z "$VAULT_TOKEN" ]]; do
		read -p 'Vault token: ' -s VAULT_TOKEN
	done
fi

# Limit to specified target
[[ -n "$TARGET" ]] && ARGS+=( -l "$TARGET" )

# Tags and skip tags
[[ -n "$TAGS" ]] && ARGS+=( -t "$TAGS" )
[[ -n "$SKIP_TAGS" ]] && ARGS+=( --skip-tags "$SKIP_TAGS" )
if $DEBUG; then
	[[ -n "$TAGS" ]] && ARGS+=( -t debug ) || ARGS+=( -t all,debug )
fi
if $INTERACTIVE; then
	[[ -n "$TAGS" ]] && ARGS+=( -t interactive ) || ARGS+=( -t all,interactive )
fi

# Quiet mode
$QUIET_MODE && ARGS+=( --skip-tags notify )

# Deployment versions
ARGS+=( -e edge_cloud_version="$EC_VERSION" )
[[ -n "$CONSOLE_VERSION" ]] && ARGS+=( -e console_version="$CONSOLE_VERSION" )

# Additional environment variables
ARGS+=( "${ENVVARS[@]}" )

# Inventory
ARGS+=( -i "$ENVIRON" )

# Playbook
if [[ -n "$PLAYBOOK_FORCED" ]]; then
	PLAYBOOK="$PLAYBOOK_FORCED"
else
	PLAYBOOK="${TARGET}.yml"
	[[ -f "$PLAYBOOK" ]] || PLAYBOOK="$DEFAULT_PLAYBOOK"
fi
ARGS+=( "$PLAYBOOK" )

echo
$DRYRUN && echo -n " [DRYRUN] "
echo "=> ansible-playbook ${ARGS[*]}"
echo
if $CONFIRM && ! $DRYRUN && ! $ASSUME_YES; then
	read -p "Are you sure you want to run this command in the \"[1;31m$ENVIRON[0m\" environment? (n) " RESP
	case "$RESP" in
	y*|Y*)	echo ;;
	*)	echo "Aborting..."; exit 0 ;;
	esac
fi

# Generate a signed SSH key
if ! $SKIP_VAULT_SSH_KEY_SIGNING; then
	: ${VAULT_SSH_TTL:=120m}

	SIGNED_KEY=$( mktemp )
	trap 'rm -f "$SIGNED_KEY"' EXIT

	if [[ -z "$VAULT_TOKEN" ]]; then
		SIGNING_TOKEN=$( VAULT_ADDR="$VAULT_ADDR" \
			vault write -field=token auth/approle/login \
			role_id=$VAULT_ROLE_ID secret_id=$VAULT_SECRET_ID )
	else
		SIGNING_TOKEN="$VAULT_TOKEN"
	fi

	VAULT_TOKEN="$SIGNING_TOKEN" VAULT_ADDR="$VAULT_ADDR" \
		vault write -field signed_key "ssh-ansible/sign/${VAULT_SSH_ROLE}" \
			public_key=@$HOME/.ssh/id_rsa.pub \
			valid_principals="ansible" \
			ttl="$VAULT_SSH_TTL" >"$SIGNED_KEY"
	[[ $? -ne 0 ]] && die "Failed to sign SSH key"

	export ANSIBLE_SSH_ARGS="-C -o ControlMaster=auto -o ControlPersist=60s -i $SIGNED_KEY -i $HOME/.ssh/id_rsa"
fi

VAULT_TOKEN="$VAULT_TOKEN" ansible-playbook "${ARGS[@]}"; RC=$?

if $DRYRUN; then
	echo
	echo "=> REMEMBER: This was a dry run!"
	echo
fi

exit "$RC"
