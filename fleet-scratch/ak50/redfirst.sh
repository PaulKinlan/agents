export HOME=/home/exedev
: > /tmp/ozmt/redfirst.result
for t in red:redtree green:C2; do
  k=${t%%:*}; d=/tmp/ozmt/${t##*:}
  cd "$d" || continue
  timeout -k 30 400 bash tests/fleet-land-message.test.sh > /tmp/ozmt/suite-$k.out 2>&1
  echo "$k rc=$? -> $(tail -1 /tmp/ozmt/suite-$k.out)" >> /tmp/ozmt/redfirst.result
  grep -E "^  - " /tmp/ozmt/suite-$k.out | sed "s/^/$k FAILED: /" >> /tmp/ozmt/redfirst.result
done
