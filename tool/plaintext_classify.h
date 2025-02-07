#include <sstream>
#include<iostream>
#include<string.h>
#include<math.h>
#include"hashutil.h"
#include<unordered_map>
#include<BOB_hash.h>

/**
 * As of July 2021, the lowmem versions of the binary fuse filters are
 * the recommended defaults.
 */
namespace xorfusefilter_classify {

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
class XorBinaryFuseFilter {
public:
  size_t size;
  size_t arrayLength;
  size_t segmentCount;
  size_t segmentCountLength;
  size_t segmentLength;
  size_t segmentLengthMask;
  static constexpr size_t arity = 3;
  FingerprintType *fingerprints;
  vector<FingerprintType> temporaryFingerprints;
  int Data_length;
  int Fingerprint_length;
  int64_t mod_data_length,mod_fingerprint_length;
  HashFamily *hasher;
  size_t hashIndex{0};

  double get_bit_per_item(){
    return (arrayLength*(Fingerprint_length+Data_length))/(size*1.0);
  }

  double get_bit_all(){
    return (arrayLength*(Fingerprint_length+Data_length));
  }

  inline __attribute__((always_inline)) size_t getHashFromHash(uint64_t hash,int index) {
    __uint128_t x = (__uint128_t)hash * (__uint128_t)segmentCountLength;
    uint64_t h = (uint64_t)(x >> 64);
    h += index * segmentLength;
    uint64_t hh = hash & ((1ULL << 36) - 1);
    h ^= (size_t)((hh >> (36 - 18 * index)) & segmentLengthMask);
    return h;
  }

  explicit XorBinaryFuseFilter(const size_t size,const size_t category_num, const int Fingerprint_length) {
    hasher = new HashFamily();
    this->Data_length=static_cast<int>(ceil(log(category_num) / log(2)));
    this->Fingerprint_length=Fingerprint_length;
    this->mod_data_length=1<<Data_length;
    this->mod_fingerprint_length=1<<Fingerprint_length;
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
    temporaryFingerprints.resize(arrayLength);
    std::fill_n(fingerprints, arrayLength, 0);
  }

  ~XorBinaryFuseFilter() {
    delete[] fingerprints;
    delete hasher;
  }

  Status AddAll(const vector<ItemType> &data, const vector<ItemType> &category,const size_t start,const size_t end) {
    return AddAll(data.data(), category.data(),start, end);
  }

  Status AddAll(const ItemType *data, const ItemType *category,const size_t start, const size_t end);

  Status Contain(const ItemType &item) const;
  std::string Info() const;
  size_t Size() const { return size; }
  size_t SizeInBytes() const { return arrayLength * sizeof(FingerprintType); }

  FingerprintType show_store_data(const ItemType &key){
    uint64_t hash = (*hasher)(key);

    __uint128_t x = (__uint128_t)hash * (__uint128_t)segmentCountLength;
    int h0 = (uint64_t)(x >> 64);
    int h1 = h0 + segmentLength;
    int h2 = h1 + segmentLength;
    uint64_t hh = hash;
    h1 ^= (size_t)((hh >> 18) & segmentLengthMask);
    h2 ^= (size_t)((hh)&segmentLengthMask);


    FingerprintType temp=fingerprints[h0] ^ fingerprints[h1] ^ fingerprints[h2];
    if(temp>>Data_length == (hash%mod_fingerprint_length)){
      return (temp % mod_data_length);
    }

    return -1;
  }

};

template <typename ItemType, typename FingerprintType, typename HashFamily>
Status XorBinaryFuseFilter<ItemType, FingerprintType, HashFamily>::AddAll(const ItemType *keys,const ItemType *category,const size_t start, const size_t end) 
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
  
  for (int i = reverseOrderPos - 1; i >= 0; i--) {
    uint64_t hash = reverseOrder[i];
    int found = reverseH[i];
    FingerprintType xor2 = ((hash%mod_fingerprint_length)<<Data_length)+record[hash]%mod_data_length;
    h012[0] = getHashFromHash(hash, 0);
    h012[1] = getHashFromHash(hash, 1);
    h012[2] = getHashFromHash(hash, 2);
    h012[3] = h012[0];
    h012[4] = h012[1];
    fingerprints[h012[found]] = xor2 ^ fingerprints[h012[found + 1]] ^ fingerprints[h012[found + 2]];
  }
  delete[] reverseOrder;
  delete[] reverseH;

  return Ok;
}
}