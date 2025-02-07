#include"xor_binary_fuse_filter.h"
#include <iostream>
#include<cmath>
#include <fstream>
#include <random>
#include <unordered_set>
#include <sstream>



int main(){
    int datasize=1000000;
    cout<<"Data size: "<<datasize<<endl;
    int category_num=285662;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0,SIZE_MAX);
    clock_t start,end;
    vector<size_t> data{};
    vector<size_t> category{};
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

    int Data_length=(int)ceil(log(category_num)/log(2));
    cout<<"Data_length: "<<Data_length<<endl;
    int fingerprint_length=4;
    cout<<"fingerprint_length:"<<fingerprint_length<<endl;
    xorfusefilter_classify::XorBinaryFuseFilter<size_t,size_t> test(datasize,category_num,fingerprint_length);
    int x1=test.AddAll(data,category,0,data.size());
    cout<<"Add success:"<<x1<<endl;

    int experiment_count=1000000;
    start = clock();
    for(int i=0;i<experiment_count;i++){
        size_t result=test.show_store_data(data[i%datasize]);
    }
    end= clock();
    cout<<"time = "<<double((end-start))/CLOCKS_PER_SEC<<"s"<<endl;
    cout<<"Query speed = "<<experiment_count/(double(end-start)/CLOCKS_PER_SEC)<<endl;

    int error=0;
    for(int j=0;j<datasize;j++){
        size_t result=test.show_store_data(data[j]);
        if(category[j]!=result){
            cout<<category[j]<<" "<<result<<endl;
            error++;
        }
    }
    cout<<"Error rate: "<<1.0*error/datasize<<endl;

    int test_times=100000,x=0,item;
    for(int i=0;i<test_times;i++){
        while (1) {
            item = dis(gen);
            if (filter.find(item) == filter.end()) {
                break;
            }
        }
        int result=test.show_store_data(item);
        if(result>=0 && result<=category_num-1)
            x++;
    }
    cout<<"Real false positive:"<<(x*1.0/test_times);

}