#include <iostream>
#include <memory>

using namespace std;

int main()
{
    std::cout << "Hello World!"<< std::endl;;

    {   int i = 0;
        int *ptr = new int;
        std::shared_ptr<int> ptr1(ptr);
        std::shared_ptr<int> ptr2(ptr);
        std::shared_ptr<int> ptr3(ptr1);
    }
    {int i = 0;}

    return 0;
}