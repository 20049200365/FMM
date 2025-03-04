#include<string.h>
#include"hashutil.h"
#include<unordered_map>
#include <random>
#include <openssl/evp.h>
#include <cstring>

namespace EFMM {

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
  typedef char byte;
public:
  size_t size;
  size_t arrayLength;
  size_t segmentCount;
  size_t segmentCountLength;
  size_t segmentLength;
  size_t segmentLengthMask;
  static constexpr size_t arity = 3;

  vector<pair<FingerprintType, FingerprintType>> EFMM_pair_type;
  FingerprintType *EFMM_integer_type;
  string enc_data;
  int fingerprint_length;
  int64_t fingerprint_mod;
  int64_t mod_cipher;
  int64_t Max_category_length;
  int64_t Max_category;
  HashFamily *hasher;
  size_t hashIndex{0};
  vector<byte> Mac_key;
  unsigned char* secret_key;
  unordered_map<uint64_t,ItemType> record;
  unordered_map<FingerprintType,ItemType> hash_to_index;

  double get_bit_all(){
      return arrayLength*(Max_category_length+fingerprint_length);
  }

  unsigned char* str2hex(char *str)
  {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len%2) == 0);
    ret = (unsigned char *)malloc(str_len/2);
    for (i =0;i < str_len; i = i+2 )
    {
      sscanf(str+i,"%2hhx",&ret[i/2]);
    }
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

  explicit VEFMM(const size_t size , const size_t category_num, const int fingerprint_length=8) {
    hasher = new HashFamily();
    this->fingerprint_length=fingerprint_length;
    this->fingerprint_mod=1<<fingerprint_length;
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
    EFMM_integer_type=new FingerprintType[arrayLength]();
    std::fill_n(EFMM_integer_type, arrayLength, 0);
    EFMM_pair_type.resize(arrayLength);
    secret_key = new unsigned char[12];
    strcpy((char *)secret_key, "example_key");

    Max_category_length=ceil(log(category_num)/log(2));
    Max_category=1<<Max_category_length;
    this->mod_cipher=1<<(fingerprint_length+Max_category_length);
  }

  ~VEFMM() {
    delete[] EFMM_integer_type;
    delete hasher;
  }

  Status AddAll(const vector<ItemType> &data, const vector<ItemType> &category,const vector<ItemType> &prf,const size_t start,const size_t end) {
    return AddAll(data.data(), category.data(), prf.data(),start, end);
  }

  Status AddAll(const ItemType *data, const ItemType *category,const ItemType * prf, const size_t start, const size_t end);

  Status Contain(const ItemType &item) const;

  std::string Info() const;

  size_t Size() const { return size; }

  size_t SizeInBytes() const { return arrayLength * sizeof(FingerprintType); }

  FingerprintType cipher_show_store_data(const ItemType &key, const ItemType &prf_value){
    uint64_t hash = (*hasher)(key);
    __uint128_t x = (__uint128_t)hash * (__uint128_t)segmentCountLength;
    int h0 = (uint64_t)(x >> 64);
    int h1 = h0 + segmentLength;
    int h2 = h1 + segmentLength;
    uint64_t hh = hash;
    h1 ^= (size_t)((hh >> 18) & segmentLengthMask);
    h2 ^= (size_t)((hh)&segmentLengthMask);

    FingerprintType temp = EFMM_integer_type[h0]^EFMM_integer_type[h1]^EFMM_integer_type[h2]^prf_value;

    if(temp>> Max_category_length == (hash)%fingerprint_mod){
      return (temp % Max_category);
    }else {
      return -1;
    }
  }

};

template <typename ItemType, typename FingerprintType, typename HashFamily>
Status VEFMM<ItemType, FingerprintType, HashFamily>::AddAll(const ItemType *keys,const ItemType *category, const ItemType *prf,const size_t start, const size_t end)
{
   uint64_t *reverseOrder = new uint64_t[size+1];
  uint8_t *reverseH = new uint8_t[size];
  size_t reverseOrderPos;
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
      hash_to_index[hash] = i;
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
      memset(EFMM_integer_type, ~0, arrayLength * sizeof(FingerprintType));
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
  std::uniform_int_distribution<FingerprintType> dis_fingerprint(0,static_cast<int>(pow(2, fingerprint_length)));
  std::uniform_int_distribution<FingerprintType> dis_cipher(0, Max_category);

  vector<int> insert_flag;
  insert_flag.resize(arrayLength);
  for (int & i : insert_flag)
    i = 0;

  for (int i = reverseOrderPos - 1; i >= 0; i--) {
    uint64_t hash = reverseOrder[i];
    int found = reverseH[i];
    FingerprintType xor2 = record[hash]%Max_category;
    FingerprintType prfValue = prf[hash_to_index[hash]];

    h012[0] = getHashFromHash(hash, 0);
    h012[1] = getHashFromHash(hash, 1);
    h012[2] = getHashFromHash(hash, 2);
    h012[3] = h012[0];
    h012[4] = h012[1];

    int Main_position=h012[found];
    insert_flag[Main_position] = 1;
    EFMM_integer_type[Main_position]=((hash%fingerprint_mod)<<Max_category_length)+xor2;
    EFMM_integer_type[Main_position]=EFMM_integer_type[Main_position]^prfValue;

    if(insert_flag[h012[found + 1]]==0){
      EFMM_integer_type[h012[found + 1]]=dis_fingerprint(gen)%mod_cipher;
      insert_flag[h012[found + 1]]=1;
    }
    if(insert_flag[h012[found + 2]]==0){
      EFMM_integer_type[h012[found + 2]]=dis_fingerprint(gen)%mod_cipher;
      insert_flag[h012[found + 2]]=1;
    }

    EFMM_integer_type[h012[found]]=EFMM_integer_type[h012[found]] ^ EFMM_integer_type[h012[found+1]] ^ EFMM_integer_type[h012[found+2]];
  }

  for (size_t i = 0; i < arrayLength; i++) {
    if(insert_flag[i]==0) {
      EFMM_integer_type[i]=dis_fingerprint(gen)%mod_cipher;
      insert_flag[i]=1;
    }
  }

  delete[] reverseOrder;
  delete[] reverseH;
  return Ok;
}

}; 