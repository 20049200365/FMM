#include "xor_binary_fuse_filter.h"
#include <iostream>
#include <random>
#include <unordered_set>
using namespace std;

int main(){

    int datasize=200000,category_num=256;
    clock_t start,end;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0,SIZE_MAX);
    vector<size_t> data{};
    vector<size_t> category{};
    unordered_set<int> filter;
    int fingerprint_length=8;
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

    EFMM::VEFMM<size_t,size_t> test(datasize,category_num,fingerprint_length);
    int x1=test.AddAll(data,category,0,data.size());
    cout<<"Add success:"<<x1<<endl;

    int cipher_error=0;
    int experiment_count=1000000;
    start = clock();
    for(int i=0;i<experiment_count;i++){
        size_t result=test.cipher_show_store_data(data[i%datasize]);
    }
    end= clock();

    cout<<"time = "<<double((end-start))/CLOCKS_PER_SEC<<"s"<<endl;
    cout<<"Query speed = "<<experiment_count/(double(end-start)/CLOCKS_PER_SEC)<<endl;
    cout<<"Memory usage: "<<test.get_bit_all()<<endl;
    cout<<"cipher_error:"<<cipher_error<<endl;

     int test_times=100000,item,fpp=0;
     for(int i=0;i<test_times;i++){
         while (1) {
             item = dis(gen);
             if (filter.find(item) == filter.end()) {
                 break;
             }
         }
         int result=test.cipher_show_store_data(item);

         if(result!=-1) {
             fpp++;
         }
     }

     cout<<"fpp = "<<fpp<<endl;
     cout<<"Real false positive:"<<(fpp*1.0/test_times);

}