#include "tool\xor_binary_fuse_filter.h"
#include <iostream>
#include <random>
#include <unordered_set>
using namespace std;

int main(){
//Generate elements
    int datasize=50000,category_num=64;
    clock_t start,end;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0,SIZE_MAX);
    vector<size_t> data{};
    vector<size_t> category{};
    string secret_key="encryptkey";
    unordered_set<int> filter;
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

    VEFMM::VEFMM<size_t,size_t> test(datasize,secret_key,7);
    
    int x1=test.AddAll(data,category,0,data.size());
    cout<<"Add success:"<<x1<<endl;

//Query
    start = clock();
    for(int search_index=0;search_index<100000;search_index++){ 
        string result=test.cipher_show_store_data(data[search_index%datasize]);
    }
    end= clock();    
    cout<<"time = "<<double((end-start))/CLOCKS_PER_SEC<<"s"<<endl;
    cout<<"Query speed = "<<100000/(double(end-start)/CLOCKS_PER_SEC)<<endl;
    cout<<"bit_per_item: "<<test.get_bit_per_item()<<endl;
}