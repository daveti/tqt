# AIK generation performance measurement for arpsec
# Jan 15, 2014
# daveti@cs.uoregon.edu
# http://davejingtian.org

#!/bin/sh

# Create the log file
touch aik_gen.log
touch arpsec_aik_gen.perf
touch tpm_aik_gen.perf

# Create the loop
i=1
while [ $i -le 100 ]
do
        ./identity_measure perf_$i wtf_key wtf_cert >> aik_gen.log
        i=`expr $i + 1`
done

# Process the log file
grep TPM_AIK_Gen aik_gen.log | cut -d [ -f2 | cut -d ] -f1 > arpsec_aik_gen.perf 
grep Tspi_TPM_CollateIdentityRequest2 aik_gen.log | cut -d [ -f2 | cut -d ] -f1 > tpm_aik_gen.perf

# Call Python time perf
echo "tpm_aik_gen:"
./perf.py ./tpm_aik_gen.perf
echo "arpsec_aik_gen:"
./perf.py ./arpsec_aik_gen.perf

# Clear the key files
#rm -rf perf_*

# Done
echo "aik_perf.sh done"

