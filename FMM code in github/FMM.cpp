#include"tool\xor_binary_fuse_filter.h"
#include <iostream>
#include<cmath>
#include <fstream>
#include <random>
#include <unordered_set>
#include <sstream>

int main(){
    int datasize=50000;//494020;
    int category_num=64;;//(int) pow(2,14);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dis(0,SIZE_MAX);
    clock_t start,end;
    vector<size_t> data{};
    vector<size_t> category{};
    const int data_chose=1; //0 means KDD99, 1 means synthetic data
    unordered_set<int> filter;

    if(data_chose==0){
        ifstream infile;
        string temp_str; 
        infile.open("KDD99.txt");
        for(int i=0;i<datasize;i++){
            infile>>temp_str;
            int item;
            istringstream ss(temp_str);
            ss >> item;
            data.push_back(i);
            category.push_back(item%category_num);
        }
    }else if(data_chose==1){
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
    }

        int Min_fingerprint_length=(int)ceil(log(category_num)/log(2));
        cout<<"Min_fingerprint_length: "<<Min_fingerprint_length<<endl;
        int real_fingerprint_length=Min_fingerprint_length+7;
        cout<<"real_fingerprint_length:"<<real_fingerprint_length<<endl;
        xorfusefilter_classify::XorBinaryFuseFilter<size_t,size_t> test(datasize,Min_fingerprint_length,real_fingerprint_length);//储存元素的个数  指纹长度
        cout<<"Bit length: "<<test.get_all_bits_num()<<endl;
        int x1=test.AddAll(data,category,0,data.size());
        cout<<"Add success:"<<x1<<endl;

        start = clock();
        for(int j=0;j<1000000;j++){
            size_t result=test.show_store_data(data[j%datasize]);
        }
        end= clock();
        cout<<"time = "<<double((end-start))/CLOCKS_PER_SEC<<"s"<<endl;
        cout<<"Query speed = "<<1000000/(double(end-start)/CLOCKS_PER_SEC)<<endl;
        cout<<"bit_per_item: "<<test.get_bit_per_item()<<endl;

        int error=0;
        start = clock();
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

        cout<<"Theoretic false positive:"<<pow(2,-(real_fingerprint_length-Min_fingerprint_length))<<endl;
        cout<<"Real false positive:"<<(x*1.0/test_times);

}
