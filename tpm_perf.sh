# TPM performance measurement for arpsec
# AIK generation is not included!
# Jan 15, 2014
# daveti@cs.uoregon.edu
# Nov 12, 2013
# daveti@cs.uoregon.edu
# http://davejingtian.org

#!/bin/sh

# Create the log file
#touch aik_gen.log
#touch arpsec_aik_gen.perf
#touch tpm_aik_gen.perf
rm *.log
rm *.perf
touch aik_quote.log
touch tpm_rand.perf
touch tpm_quote.perf
touch tpm_verify.perf
touch tpm_attest_verify.perf

# Create the loop
i=1
while [ $i -le 100 ]
do
        #./identity_measure perf_$i >> aik_gen.log
	./aikquote_measure >> aik_quote.log
        i=`expr $i + 1`
done

# Process the log file
#grep TPM_AIK_Gen aik_gen.log | cut -d [ -f2 | cut -d ] -f1 > arpsec_aik_gen.perf 
#grep Tspi_TPM_CollateIdentityRequest aik_gen.log | cut -d [ -f2 | cut -d ] -f1 > tpm_aik_gen.perf
grep Tspi_TPM_GetRandom aik_quote.log | cut -d [ -f2 | cut -d ] -f1 > tpm_rand.perf
grep Tspi_TPM_Quote aik_quote.log | cut -d [ -f2 | cut -d ] -f1 > tpm_quote.perf
grep Tspi_Hash_VerifySignature aik_quote.log | cut -d [ -f2 | cut -d ] -f1 > tpm_verify.perf
grep TPM_Verify aik_quote.log | cut -d [ -f2 | cut -d ] -f1 > tpm_attest_verify.perf 

# Call Python time perf
echo "tpm_rand:"
./perf.py ./tpm_rand.perf
echo "tpm_quote:"
./perf.py ./tpm_quote.perf
echo "tpm_verfiy:"
./perf.py ./tpm_verify.perf
echo "tpm_attest_verify:"
./perf.py ./tpm_attest_verify.perf

# Clear the key files
#rm -rf perf_*

# Done
echo "tpm_perf.sh done"

