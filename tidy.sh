for i in *.png; do
    [ -f "$i" ] || break
    mv "$i" "charts/$i"
done