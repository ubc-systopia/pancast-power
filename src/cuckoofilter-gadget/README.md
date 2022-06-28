# cuckoofilter-gadget
Sample C code that implements the reconstruction and lookup functionality of a cuckoo filter from a byte array.

## Running instructions:
1. Have an environment ready where you can run C programs (I use VSCode with Ubuntu WSL2. Is pretty good)
2. Clone this repo
3. Run `bash compile`
4. Run `./decode`

## FAQ
1. Why is this code so spaghetti?<br>
A. Trying to refactor decode.c into multiple, more logical files somehow changed pointer addresses when calling functions from different files. 
2. What is this `metrohash-c` thing that I need to clone?<br>
A. `metrohash-c` implements a particular type of hashing function which mirrors the one used by the backend.
