# webfuzz

pipx install -e .

pipx install git+https://github.com/Goultarde/webfuzz

webfuzz -u http://$DOMAIN

cat webfuzz_* | sort -u | grep "status: 200" -i
