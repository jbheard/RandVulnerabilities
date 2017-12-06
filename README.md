# CP460 Final Project Codebase

This project demonstrates some simple vulnerabilities of using weak PRNGs. There are 3 attacks which are highlighted:
  
1. *break_time.c* This attack focuses on a small keyspace. In particular, the commonly used seed of a Unix timestamp is implemented to seed a PRNG. If it is known what year some numbers were generated, it only takes approx 2^25 attempts to find the initial seed.  
2. *break_rand.c* This attack searches the entire possible seed space of the PRNG implementation (portable rand() as defined by ISO/IEC 9899:1999). This demonstrates that a computationally infeasible periodicity is a necessessity for a secure PRNG.  
3. *break_algorithm.c* This is a probabalistic attack that takes two consecutive outputs of rand and finds potential internal states of rand(). This algorithm can be ran multiple times on the same seed to find the correct state with high probability. This means despite not knowing the seed, we can predict all future outputs of rand().

These are only 3 common vulnerabilities, and can be applied to other weak PRNGs.
