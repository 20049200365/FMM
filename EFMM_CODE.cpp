#include "xor_binary_fuse_filter.h"
#include <iostream>
#include <random>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <unordered_set>
using namespace std;

size_t calculatePRF(size_t a, const unsigned char* key, size_t keyLen) {
    unsigned char inputBytes[sizeof(size_t)];
    std::memcpy(inputBytes, &a, sizeof(size_t));

    const EVP_MD* md = EVP_sha256();
    unsigned char prfResult[EVP_MAX_MD_SIZE];
    unsigned int prfLen = 0;

    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, keyLen, md, nullptr);
    HMAC_Update(ctx, inputBytes, sizeof(size_t));
    HMAC_Final(ctx, prfResult, &prfLen);
    HMAC_CTX_free(ctx);

    size_t result = 0;
    std::memcpy(&result, prfResult, sizeof(size_t));

    return result;
}

int main(){

    int datasize=600000,category_num=258;
    clock_t start,end;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0,SIZE_MAX);
    vector<size_t> data{};
    vector<size_t> category{};
    vector<size_t> prf{};
    unordered_set<int> filter;
    int fingerprint_length=8;
    int Max_category_length=ceil(log(category_num)/log(2));
    size_t mod=1<<(Max_category_length+fingerprint_length);

    for(int i=0;i<datasize;i++){
        int item;
        while (1)
        {
            item = dis(gen);
            if (filter.find(item) == filter.end()) {
                filter.insert(item);
                break;
            }
        }
        data.push_back(item);
        category.push_back(i%category_num);
    }
    prf.resize(datasize);

    unsigned char *secret_key = new unsigned char[12];
    strcpy((char *)secret_key, "example_key");
    for (int i=0;i<datasize;i++) {
        prf[i]=calculatePRF(data[i],secret_key,strlen((char *)secret_key))%mod;
    }


    EFMM::VEFMM<size_t,size_t> test(datasize,category_num,fingerprint_length);
    int x1=test.AddAll(data,category,prf,0,data.size());
    cout<<"Add success:"<<x1<<endl;

    int error=0;
    for (int i=0;i<datasize;i++) {
        size_t result=test.cipher_show_store_data(data[i%datasize],prf[i%datasize]);
        if(category[i]!=result){
            error++;
        }
    }
    cout<<"Error number: "<<error<<endl;
    cout<<"Error rate: "<<1.0*error/datasize<<endl;

    int experiment_count=1000000;
    start = clock();
    for(int i=0;i<experiment_count;i++){
        size_t result=test.cipher_show_store_data(data[i%datasize],prf[i%datasize]);
    }
    end= clock();

    cout<<"time = "<<double((end-start))/CLOCKS_PER_SEC<<"s"<<endl;
    cout<<"Query speed = "<<experiment_count/(double(end-start)/CLOCKS_PER_SEC)<<endl;
    cout<<"Memory usage: "<<test.get_bit_all()<<endl;

    int test_times=1000000,item,fpp=0;
    for(int i=0;i<test_times;i++){
        while (1) {
            item = dis(gen);
            if (filter.find(item) == filter.end()) {
                break;
            }
        }

        size_t prf_value=calculatePRF(item,secret_key,strlen((char *)secret_key))%mod;
        int result=test.cipher_show_store_data(item,prf_value);

        if(result!=-1) {
            fpp++;
        }
    }

    cout<<"fpp = "<<fpp<<endl;
    cout<<"theoretical false positives:"<<pow(2,-1*fingerprint_length)<<endl;
    cout<<"Real false positive:"<<(fpp*1.0/test_times);

}