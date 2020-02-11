for protocol in "secure_scan" "standard"
do
    for s in 10 100 1000 10000
    do
        for a in 10 100 1000 10000
        do
            for p in 0.0001 0.001 0.01 0.1
            do
                echo "python3 -m simulation --csv results.csv -n 10000 -b --protocol $protocol -s $s -a $a -p $p"
                python3 -m simulation --csv results.csv -n 10000 -b --protocol $protocol -s $s -a $a -p $p
            done
        done
    done
done