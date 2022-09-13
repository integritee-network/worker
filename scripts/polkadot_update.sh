#!/bin/bash

# A script to automate the polkadot update for our repository as far as possible
# Needs the diener and sd (sed replacement) tool. Install with:
# cargo install diener
# cargo install sd

# These are the values that need to be adjusted for an update
CHECKOUT_DIR="$HOME/polkadot_update2"
DEVELOPER_ID="tn"
OLD_VERSION_NUMBER="0.9.27"
NEW_VERSION_NUMBER="0.9.28"
NEW_NIGHTLY_VERSION="2022-09-12"

OLD_POLKADOT_VERSION_NUMBER="polkadot-v${OLD_VERSION_NUMBER}"
NEW_POLKADOT_VERSION_NUMBER="polkadot-v${NEW_VERSION_NUMBER}"
DEVELOPMENT_BRANCH="${DEVELOPER_ID}/${NEW_POLKADOT_VERSION_NUMBER}"

# Make sure that the directory does not exist. We don't want to mess up existing stuff
if [ -d "${CHECKOUT_DIR}" ]; then
  echo "Directory ${CHECKOUT_DIR} already exists. Please delete directory first."
  exit 1
fi

mkdir "${CHECKOUT_DIR}"
pushd "${CHECKOUT_DIR}"

git clone https://github.com/integritee-network/integritee-node.git
git clone https://github.com/integritee-network/pallets.git
git clone https://github.com/integritee-network/parachain.git
git clone https://github.com/scs/substrate-api-client.git
git clone https://github.com/integritee-network/worker.git

declare -a REPO_NAMES=("integritee-node" "pallets" "parachain" "substrate-api-client" "worker" )

# Create new branch for all repos
for REPO in ${REPO_NAMES[@]}; do
   pushd ${REPO};git checkout -b ${DEVELOPMENT_BRANCH};popd
done

# Update the polkadot version
# We cannot combine the flags into a single call. Don't use the all flag because it relly changes all dependencies
diener update --cumulus --branch ${NEW_POLKADOT_VERSION_NUMBER}
diener update --substrate --branch ${NEW_POLKADOT_VERSION_NUMBER}
# Polkadot uses another branch pattern, because why not...
diener update --polkadot --branch "release-v${NEW_VERSION_NUMBER}"

# Add commit for all repos
for REPO in ${REPO_NAMES[@]}; do
   pushd ${REPO};git add -A;git commit -m "Update polkadot version (Auto generated commit)";popd
done

# Execute cargo update for all repos. Currently not active as it is not clear when is the "right moment" to do this
#for REPO in ${REPO_NAMES[@]}; do
#   pushd ${REPO};cargo update;popd
#done

# Add commit for all repos
#for REPO in ${REPO_NAMES[@]}; do
#   pushd ${REPO};git add -A;git commit -m "Run cargo update (Auto generated)";popd
#done

#set -o xtrace
# Update internal dependencies by doing search replace
for REPO in ${REPO_NAMES[@]}; do
   SEARCH_STRING_VERSION="${REPO}\", branch = \"${OLD_POLKADOT_VERSION_NUMBER}\""
   SEARCH_STRING_VERSION_GIT="${REPO}.git\", branch = \"${OLD_POLKADOT_VERSION_NUMBER}\""
   SEARCH_STRING_MASTER="${REPO}\", branch = \"master\""
   SEARCH_STRING_MASTER_GIT="${REPO}.git\", branch = \"master\""
   REPLACE_STRING="${REPO}.git\", branch = \"${DEVELOPMENT_BRANCH}\""
   sd "${SEARCH_STRING_VERSION}" "${REPLACE_STRING}" $(find . -type f -name 'Cargo.toml')
   sd "${SEARCH_STRING_VERSION_GIT}" "${REPLACE_STRING}" $(find . -type f -name 'Cargo.toml')
   sd "${SEARCH_STRING_MASTER}" "${REPLACE_STRING}" $(find . -type f -name 'Cargo.toml')
   sd "${SEARCH_STRING_MASTER_GIT}" "${REPLACE_STRING}" $(find . -type f -name 'Cargo.toml')
done

# Add commit for all repos
for REPO in ${REPO_NAMES[@]}; do
   pushd ${REPO};git add -A;git commit -m "Update versions for internal dependencies (Auto generated commit)";popd
done

NIGHTLY_SEARCH_STRING="channel = \"nightly-.*\""
NIGHTLY_SEARCH_STRING="channel = \"nightly-${NEW_NIGHTLY_VERSION}\""
sd "${NIGHTLY_SEARCH_STRING}" "${NIGTHLY_NEW_STRING}" $(find . -type f -name 'rust-toolchain.toml')

# Add commit for all repos
for REPO in ${REPO_NAMES[@]}; do
   pushd ${REPO};git add -A;git commit -m "Update rust toolchain to new nightly version (Auto generated commit)";popd
done

echo ""
echo ""
echo "Search results for old version number ${OLD_VERSION_NUMBER} in Cargo.toml files:"
# Exclude the lock files as they still refer to the old version
grep -F -r --exclude *.lock "${OLD_VERSION_NUMBER}" .

popd
