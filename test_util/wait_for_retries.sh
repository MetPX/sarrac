#!/bin/bash
echo "Waiting for retries to finish..."
stalled=0
stalled_value=-1
retry_msgcnt="$(cat ~/.cache/sr3/subscribe/local_copy/*retry* 2>/dev/null | sort -u | wc -l)"
while [ $retry_msgcnt -gt 0 ]; do
        printf "${flow_test_name} Still %4s messages to retry, waiting...\n" "$retry_msgcnt"
        sleep 15
        retry_msgcnt="$(cat ~/.cache/sr3/subscribe/local_copy/*retry* 2>/dev/null | sort -u | wc -l)"

        if [ "${stalled_value}" == "${retry_msgcnt}" ]; then
              stalled=$((stalled+1));
              if [ "${stalled}" == 5 ]; then
                 printf "\n    Warning some retries stalled, skipping..., might want to check the logs\n\n"
                 retry_msgcnt=0
              fi
        else
              stalled_value=$retry_msgcnt
              stalled=0
        fi
done
