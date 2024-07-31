#include <sstream>
#include<iostream>
#include<string.h>
#include<math.h>
#include"hashutil.h"
#include<unordered_map>
#include"aes.h"
#include <random>

typedef char byte;
namespace VEFMM {

enum Status {
  Ok = 0,
  NotFound = 1,
  NotEnoughSpace = 2,
  NotSupported = 3,
};

__attribute__((always_inline)) inline uint32_t reduce(uint32_t hash,uint32_t n) {
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

__attribute__((always_inline)) inline uint8_t mod3(uint8_t x) {
    if (x > 2) {
        x -= 3;
    }
    return x;
}

template <typename ItemType, typename FingerprintType,typename HashFamily = hashing::SimpleMixSplit>
class VEFMM {
public:
  size_t size;
  size_t arrayLength;
  size_t segmentCount;
  size_t segmentCountLength;
  size_t segmentLength;
  size_t segmentLengthMask;
  static constexpr size_t arity = 3;
  FingerprintType *fingerprints;
  vector<pair<uint64_t, string>> EFMM;
  string enc_data;
  int fingerprint_length;
  int64_t mod;
  HashFamily *hasher;
  string secret_key;
  bool is_verify=false;
  size_t hashIndex{0};
  vector<byte> Mac_key;

  double get_bit_per_item(){
      return (EFMM.size()*(128+fingerprint_length))/(size*1.0);
  }
  
  inline FingerprintType fingerprint(const uint64_t hash) const {
    FingerprintType ret=(FingerprintType)hash;
    ret=ret%mod;
    return ret;
  }

  inline __attribute__((always_inline)) size_t getHashFromHash(uint64_t hash,int index) {
    __uint128_t x = (__uint128_t)hash * (__uint128_t)segmentCountLength;
    uint64_t h = (uint64_t)(x >> 64);
    h += index * segmentLength;
    uint64_t hh = hash & ((1ULL << 36) - 1);
    h ^= (size_t)((hh >> (36 - 18 * index)) & segmentLengthMask);
    return h;
  }

  explicit VEFMM(const size_t size,string key,const int64_t fingerprint_length=8) {
    hasher = new HashFamily();
    this->fingerprint_length=fingerprint_length;
    this->mod=1<<fingerprint_length;
    this->size = size;
    this->segmentLength = calculateSegmentLength(arity, size);
    if (this->segmentLength > (1 << 18)) {
      this->segmentLength = (1 << 18);
    }
    double sizeFactor = calculateSizeFactor(arity, size);
    size_t capacity = size * sizeFactor;

    size_t segmentCount = (capacity + segmentLength - 1) / segmentLength - (arity - 1);
    this->arrayLength = (segmentCount + arity - 1) * segmentLength;
    this->segmentLengthMask = this->segmentLength - 1;
    this->segmentCount = (this->arrayLength + this->segmentLength - 1) / this->segmentLength;
    this->segmentCount = this->segmentCount <= arity - 1 ? 1 : this->segmentCount - (arity - 1);

    this->arrayLength = (this->segmentCount + arity - 1) * this->segmentLength;
    this->segmentCountLength = this->segmentCount * this->segmentLength;
    fingerprints = new FingerprintType[arrayLength]();
    std::fill_n(fingerprints, arrayLength, 0);
    EFMM.resize(arrayLength);
    this->secret_key=key;
  }

  ~VEFMM() {
    delete[] fingerprints;
    delete hasher;
  }

  Status AddAll(const vector<ItemType> &data, const vector<ItemType> &category,const size_t start,const size_t end) {
    return AddAll(data.data(), category.data(),start, end);
  }

  Status AddAll(const ItemType *data, const ItemType *category,const size_t start, const size_t end);

  Status Contain(const ItemType &item) const;

  std::string Info() const;

  // number of current inserted items;
  size_t Size() const { return size; }

  // size of the filter in bytes.
  size_t SizeInBytes() const { return arrayLength * sizeof(FingerprintType); }

  int find_category(const ItemType &key){
    return 0;
  }

  void show_fingerprint(const ItemType &key){
    uint64_t hash = (*hasher)(key);
    FingerprintType f = fingerprint(hash);
    cout<<"fingerprint: "<<f<<endl;
  }

  string cipher_show_store_data(const ItemType &key){
    uint64_t hash = (*hasher)(key);
    __uint128_t x = (__uint128_t)hash * (__uint128_t)segmentCountLength;
    int h0 = (uint64_t)(x >> 64);
    int h1 = h0 + segmentLength;
    int h2 = h1 + segmentLength;
    uint64_t hh = hash;
    h1 ^= (size_t)((hh >> 18) & segmentLengthMask);
    h2 ^= (size_t)((hh)&segmentLengthMask);
    string ret=string_xor(string_xor(EFMM[h0].second,EFMM[h1].second),EFMM[h2].second);
    uint64_t fingerprint_of_ret=EFMM[h0].first^EFMM[h1].first^EFMM[h2].first;
    uint64_t fingerprint_of_query=((*hasher)(string_to_int(ret)))%mod;
    if(fingerprint_of_query!=fingerprint_of_ret)
      cout<<"No store"<<endl;
    return ret;
  }

  string string_xor(string A,string B){
      if(A.empty())
        return B;
      if(B.empty())
        return A;

      if(A.size()!=B.size()){
        exit(-1);
      }else{
        string ret;
        for(int i=0;i<A.size();i++){
          ret.push_back(A[i]^B[i]);
        }
        return ret;
      }
  }

  vector<byte> byte_xor(vector<byte> b1,vector<byte> b2){
    if(b1.empty()){
      return b2;
    }
    if(b2.empty()){
      return b1;
    }
    if(b1.size()!=b2.size()){
      cout<<"size error"<<endl;
      exit(-1);
    }
    else{
      vector<byte> ret(b1.size());
      for(int i=0;i<b1.size();i++)
        ret[i]=b1[i]^b2[i];
      return ret;
    }
  }

  string get_random_str(int length){
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count(); 
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dis(-128,127);

    string ret;
    ret.resize(length);
    for(int i=0;i<length;i++){
      ret[i]=dis(gen);
    }
    return ret;
  }

  void set_verification(bool is_verify){
    this->is_verify=is_verify;
  }

  vector<byte> string_to_byte(string str){
    if(!str.empty()){
      vector<byte> ret;
      for(int i=0;i<str.size();i++){
        ret.push_back(str[i]);
      }
      return ret;
    }else{
      vector<byte> ret(16);
      for(int i=0;i<ret.size();i++)
        ret[i]=0;
      return ret;
    }
  }

  string byte_to_string(vector<byte> byte_data){
    string ret;
    if(!byte_data.empty()){
      for(int i=0;i<byte_data.size();i++)
        ret.push_back(byte_data[i]);
    }
    return ret;
  }  

  int string_to_int(string str){
      int ret=0,index=0;
      int temp[4];
      for (int i = 0; i < 4; i++)
      {
          temp[i]=0;
      }
      for (int i = 0; i < str.size(); i++)
      {   
          temp[index]=temp[index]^(int)str[i];
          index=(index+1)%4;
      }
      ret=temp[0]<<24+temp[1]<<16+temp[2]<<8+temp[3];
      return ret;
  }
};

template <typename ItemType, typename FingerprintType, typename HashFamily>
Status VEFMM<ItemType, FingerprintType, HashFamily>::AddAll(const ItemType *keys,const ItemType *category,const size_t start, const size_t end) 
{
  uint64_t *reverseOrder = new uint64_t[size+1];
  uint8_t *reverseH = new uint8_t[size];
  size_t reverseOrderPos;
  unordered_map<uint64_t,ItemType> record;
  uint8_t *t2count = new uint8_t[arrayLength];
  
  uint64_t *t2hash = new uint64_t[arrayLength];
  size_t *alone = new size_t[arrayLength];
  hashIndex = 0;
  
  size_t h012[5];
  
  while (true) {
    memset(t2count, 0, sizeof(uint8_t) * arrayLength);
    memset(t2hash, 0, sizeof(uint64_t) * arrayLength);

    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    reverseOrder[size] = 1;

    int blockBits = 1;
    while((size_t(1)<<blockBits) < segmentCount) { blockBits++; }
    size_t block = size_t(1) << blockBits;

    size_t *startPos = new size_t[block];
    for(uint32_t i = 0; i < uint32_t(1) << blockBits; i++) { startPos[i] = i * size / block; }

    for (size_t i = start; i < end; i++) {
      uint64_t k = keys[i];
      uint64_t hash = (*hasher)(k);
      size_t segment_index = hash >> (64 - blockBits);
      while(reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= (size_t(1) << blockBits) - 1;
      }
      reverseOrder[startPos[segment_index]] = hash;
      record[hash]=category[i];
      startPos[segment_index]++;
    }

    uint8_t countMask = 0;
    for (size_t i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      for (int hi = 0; hi < 3; hi++) {
        int index = getHashFromHash(hash, hi);
        t2count[index] += 4;
        t2count[index] ^= hi;
        t2hash[index] ^= hash;
        countMask |= t2count[index];
      }
    }
    delete[] startPos;

    if (countMask >= 0x80) {
      memset(fingerprints, ~0, arrayLength * sizeof(FingerprintType));
      return Ok;
    }

    reverseOrderPos = 0;
    size_t alonePos = 0;
    for (size_t i = 0; i < arrayLength; i++) {
      alone[alonePos] = i;
      int inc = (t2count[i] >> 2) == 1 ? 1 : 0;
      alonePos += inc;
    }

    while (alonePos > 0) {
      alonePos--;
      size_t index = alone[alonePos];
      if ((t2count[index] >> 2) == 1) {
        uint64_t hash = t2hash[index];
        int found = t2count[index] & 3;
        
        reverseH[reverseOrderPos] = found;
        reverseOrder[reverseOrderPos] = hash;

        h012[0] = getHashFromHash(hash, 0);
        h012[1] = getHashFromHash(hash, 1);
        h012[2] = getHashFromHash(hash, 2);
        size_t index3 = h012[mod3(found + 1)];
        alone[alonePos] = index3;
        alonePos += ((t2count[index3] >> 2) == 2 ? 1 : 0);
        t2count[index3] -= 4;
        t2count[index3] ^= mod3(found + 1);
        t2hash[index3] ^= hash;

        index3 = h012[mod3(found + 2)];
        alone[alonePos] = index3;
        alonePos += ((t2count[index3] >> 2) == 2 ? 1 : 0);
        t2count[index3] -= 4;
        t2count[index3] ^= mod3(found + 2);
        t2hash[index3] ^= hash;

        reverseOrderPos++;
      }
    }

    if (reverseOrderPos == size) {
      break;
    }
    hashIndex++;

    delete hasher;
    hasher = new HashFamily();
  }
  
  delete[] alone;
  delete[] t2count;
  delete[] t2hash;
  
  unsigned seed = std::chrono::system_clock::now().time_since_epoch().count(); 
  std::mt19937 gen(seed);
  std::uniform_int_distribution<size_t> dis_fingerprint(0,(int)pow(2,fingerprint_length));

  for (int i = reverseOrderPos - 1; i >= 0; i--) {
    uint64_t hash = reverseOrder[i];
    int found = reverseH[i];
    FingerprintType xor2 = record[hash];

    aes tool;
    string plaintext=to_string(xor2);
    string temp=tool.encrypt_cbc(tool.S_BOX,plaintext,secret_key);
    uint64_t fingerprint_of_c= ((*hasher)(string_to_int(temp)))%mod;
    h012[0] = getHashFromHash(hash, 0);
    h012[1] = getHashFromHash(hash, 1);
    h012[2] = getHashFromHash(hash, 2);
    h012[3] = h012[0];
    h012[4] = h012[1];

    EFMM[h012[found]].second=temp;
    EFMM[h012[found]].first=fingerprint_of_c;
    
    if(EFMM[h012[found + 1]].second.empty()){
      EFMM[h012[found + 1]].second=get_random_str(16);
      EFMM[h012[found + 1]].first=dis_fingerprint(gen);
    }
    EFMM[h012[found]].second=string_xor(EFMM[h012[found]].second,EFMM[h012[found + 1]].second);
    EFMM[h012[found]].first=EFMM[h012[found]].first ^EFMM[h012[found+1]].first;

    if(EFMM[h012[found + 2]].second.empty()){
      EFMM[h012[found + 2]].second=get_random_str(16);
      EFMM[h012[found + 2]].first=dis_fingerprint(gen);
    }
    EFMM[h012[found]].second=string_xor(EFMM[h012[found]].second,EFMM[h012[found + 2]].second);
    EFMM[h012[found]].first=EFMM[h012[found]].first ^EFMM[h012[found+2]].first;

    fingerprints[h012[found]] = xor2 ^ fingerprints[h012[found + 1]] ^ fingerprints[h012[found + 2]];
  }
  delete[] reverseOrder;
  delete[] reverseH;

  return Ok;
}

}; 