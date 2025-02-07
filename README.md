# Dataset
  
  Online Retail: https://archive.ics.uci.edu/dataset/352/online+retail.

  MAWI: http://mawi.nezu.wide.ad.jp/mawi/..

  CTU-13: https://mcfp.weebly.com/the-ctu-13-dataset-a-labeled-dataset-with-botnet-normal-and-background-traffic.html.

# Run code
  Generate build script
    ```C++
    cmake .
    ```
  
  Execute build and installation
    ```C++
    make && make install
    ```

# Result
  
  Run FMM_CODE.cpp as an example. The result is as follows.
  
  ```C++
  Data size: 1000000
  Data_length: 19
  fingerprint_length:4
  Add success:0
  time = 0.018869s
  Query speed = 5.2997e+07
  Error rate: 0
  Real false positive:0.03408
  ```
