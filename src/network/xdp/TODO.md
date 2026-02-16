- check if node-wide  stats is enough: no
- simplify the code: done
- reproduce experiment: show that the solution works
   - nginx
   - alert
- write down experiment
- write background
- experiment: meansure solution overhead
- focus on document

the idea is to detect noisy neighboars
for that, I need to know if a pod is receiving too much data compared to other pods
right now i have a list of pods with the packet count: pod -> packet count
c
c][c]


BETTER TO USE per-pod historical data
and not cluster wide mean

better not to flag an anomaly when a pod is receiving lots of packets compared to other pooods on the node
because a pod might be going through a high demand period, while other pods might not
this would cause an anomaly, but might not necessarily be one

we should flag anomalies when a pod is receiving lots of packets compared to its historical usage
