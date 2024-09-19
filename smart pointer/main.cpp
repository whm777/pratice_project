#include "my_unique_ptr.hpp"
#include <cassert>

int main()
{

    //start 测试unique_ptr
    //指针只允许指向一个对象，一一对应，
    My_unique_ptr<int> p1(new int(10));
    std::cout << *p1 << std::endl;
    My_unique_ptr<int> p2 = std::move(p1);//可以移动
    My_unique_ptr<int> p3(nullptr);
    //p3 = p1;//不可以复制
    //My_unique_ptr<int> p4(p1);  //禁止拷贝构造
    assert(!p1);
    std::cout << *p2 << std::endl;

    //end 测试unique_ptr


    

    return 0;
}