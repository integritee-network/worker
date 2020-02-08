# a few examples to be run in top dir
find . -type f -name "Cargo.toml" -print0 | xargs -0 sed -i 's/https:\/\/github.com\/paritytech\/substrate/https:\/\/github.com\/scs\/substrate/g' {} \;