# C Rand Vulnerabilities

This project demonstrates some simple vulnerabilities of using weak PRNGs, with a portable C rand implementation used as an example. The goal of this project is to highlight why choice of random number generator is important when trying to create secure randomness (e.g. keys, IVs, &c). There are 3 attacks which are highlighted:
  
1. *seed_time.c* This attack focuses on a small keyspace. In particular, the commonly used seed of a Unix timestamp is implemented to seed a PRNG. If it is known what year some numbers were generated, it only takes approx 2^25 attempts to find the initial seed. This means that as long as we know what century the key was generated in, it is easy to test all possible timestamps very quickly.  
2. *periodicity.c* This attack searches the entire possible seed space of the PRNG implementation (portable rand() as defined by ISO/IEC 9899:1999). This shows that the periodicity of a PRNG must be infeasible to brute-force.  
3. *probab.c* This is a probabalistic attack that takes two consecutive outputs of rand and finds potential internal states of rand(). This algorithm can be ran multiple times on the same seed to find the correct state with high probability. This means despite not knowing the initial seed, we can predict all future outputs of rand().

These are only a few common vulnerabilities that can be applied to other weak PRNGs. For generating secure random numbers, be sure to use a secure cryptographic PRNG (CSPRNG) such as [LavaRND](http://www.lavarnd.org/), or a strong cipher (like AES in counter mode), and seed the algorithm with pure random data (/dev/urandom is generally safe, as well as camera/microphone noise, &c).
