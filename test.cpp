#include <iostream>


int main(){

int a = 5;
int &ref_a_left = a;
int &&ref_a_right = std::move(a);

ref_a_right = 10;
std::cout << ref_a_left << std::endl;
std::cout << a << std::endl;
std::cout << ref_a_right << std::endl;
ref_a_left = 20;
std::cout << ref_a_left << std::endl;
std::cout << a << std::endl;
std::cout << ref_a_right << std::endl;
a = 30;

std::cout << ref_a_left << std::endl;
std::cout << a << std::endl;
std::cout << ref_a_right << std::endl;

std::cout<< "****************"<<std::endl;
int b = ref_a_right;
std::cout << ref_a_left << std::endl;
std::cout << a << std::endl;
std::cout << ref_a_right << std::endl;
std::cout << b << std::endl;
b = 100;
std::cout << ref_a_left << std::endl;
std::cout << a << std::endl;
std::cout << ref_a_right << std::endl;
std::cout << b << std::endl;

    return 0;
}