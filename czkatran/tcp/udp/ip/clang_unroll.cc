// file name: test_performance.cu
#include <stdio.h>
//#include <cuda_runtime.h>
//#include "cublas_v2.h"
#include <unistd.h>
#include <chrono>
#include <iostream>
#include <string>
using namespace std;
 
void test_cpu_1(int count, const char* name)
{  
    int sum = 0;
 
    auto start = std::chrono::system_clock::now();
    for(int i = 0;i < count;i++){  
        sum += i;
    }
    auto end = std::chrono::system_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << name <<" cost time: "<< dura.count() << " microseconds" << std::endl;
    printf("                                                   sum = %d\n",sum);
}
 
 
void test_cpu_2(int count, const char* name)
{
    int sum = 0;
    auto start = std::chrono::system_clock::now();
    for(int i=0; i<count; i+=4)
    {
        sum += i;
        sum += i+1;
        sum += i+2;
        sum += i+3;
    }
    auto end = std::chrono::system_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << name <<" cost time: "<< dura.count() << " microseconds" << std::endl;
    printf("                                                   sum = %d\n",sum);
 
}
 
void test_cpu_3(int count, const char* name)
{
    int sum = 0;
    int sum1=0,sum2=0,sum3=0, sum4=0;
 
    auto start = std::chrono::system_clock::now();
    for(int i=0;i < count;i+=4){
        sum1 += i;
        sum2 += i+1;
        sum3 += i+2;
        sum4 += i+3;
    }
    sum = sum1+sum2+sum3+sum4;
    auto end = std::chrono::system_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << name <<" cost time: "<< dura.count() << " microseconds" << std::endl;
    printf("                                                   sum = %d\n",sum);
 
}
 
/*__global__ void progam_kernel1(int* sum, int count)
{
    for(int i = 0;i < count;i++){  
        *sum += i;
    }
    
}
 
__global__ void progam_kernel2(int* sum, int count)
{
    #pragma unroll
    for(int i = 0;i < count;i++){  
        *sum += i;
    }
}
 
void test_cuda_1(int count, const char* name)
{
    int sum =0;
    int* g_sum;
    cudaMalloc((void **)&g_sum, sizeof(int) * 1);
    cudaMemcpy(g_sum, &sum, 1 * sizeof(int),cudaMemcpyHostToDevice);
 
    auto start = std::chrono::system_clock::now();
    progam_kernel1<<<1,1>>>(g_sum, count); //调用核函数
    auto end = std::chrono::system_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << name <<" cost time: "<< dura.count() << " microseconds" << std::endl;
 
    cudaMemcpy(&sum, g_sum, sizeof(int) * 1, cudaMemcpyDeviceToHost);
    printf("                                                   sum = %d\n",sum);
    cudaFree(g_sum); 
 
}
 
void test_cuda_2(int count, const char* name)
{
    int sum =0;
    int* g_sum;
    cudaMalloc((void **)&g_sum, sizeof(int) * 1);
    cudaMemcpy(g_sum, &sum, 1 * sizeof(int),cudaMemcpyHostToDevice);
 
    auto start = std::chrono::system_clock::now();
    progam_kernel2<<<1,1>>>(g_sum, count); //调用核函数
    auto end = std::chrono::system_clock::now();
    auto dura = std::chrono::duration_cast<std::chrono::microseconds> (end - start);
    std::cout << name <<" cost time: "<< dura.count() << " microseconds" << std::endl;
 
    cudaMemcpy(&sum, g_sum, sizeof(int) * 1, cudaMemcpyDeviceToHost);
    printf("                                                   sum = %d\n", sum);
    cudaFree(g_sum);  
 
}*/
 
void test_performance()
{
    int count =100000;
    std::string s1 ="cpu origin";
    std::string s2 = "cpu pragma unroll";
    std::string s21 = "cpu pragma unroll_1";
    //std::string s3 = "cuda origin";
    //std::string s4 = "cuda pragma unroll";
 
    test_cpu_1(count, s1.c_str());
    test_cpu_2(count, s2.c_str());
    test_cpu_3(count, s21.c_str());
    //test_cuda_1(count, s3.c_str());
    //test_cuda_2(count, s4.c_str());
 
 
}
 
int main(int argc, char *argv[]) 
{
    test_performance();
    return 0;
 
}