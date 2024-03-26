#!/bin/bash
rep=({0..3})
if [[ $# -gt 0 ]]; then
    rep=($@)
fi

# avoid stack overflow as in our simple demo the bootstrapping replica will
# potentially have a long chain of promise resolution
ulimit -s unlimited

for i in "${rep[@]}"; do
    echo "starting replica $i"
    #valgrind --leak-check=full ./examples/hotstuff-app --conf hotstuff-sec${i}.conf > log${i} 2>&1 &
    #gdb -ex r -ex bt -ex q --args ./examples/hotstuff-app --conf hotstuff-sec${i}.conf > log${i} 2>&1 &
    ./examples/hotstuff-app --conf ./hotstuff-frost-sec${i}.conf > log${i} 2>&1 &
    #./examples/hotstuff-app --conf ./hotstuff-frost-sec${i}.conf > log${i}_frost 2> error${i}_frost &
    #strace -o trace_output.txt ./examples/hotstuff-app --conf ./hotstuff-frost-sec${i}.conf > log${i}_frost 2> error${i}_frost &
   # gdb -ex "run --conf hotstuff-sec${i}.conf" --args ./examples/hotstuff-app > log${i} 2>&1 &



      # gdb -ex r -ex bt -ex q --args ./examples/hotstuff-app --conf ./hotstuff-frost-sec${i}.conf > log${i}_frost 2>&1 &


done
wait
