/*
测试explicit 关键字
在没有这个关键字的情况下被隐式转换的情况

*/
#include <iostream>

class MyClass{
    public:
        explicit MyClass(int value){
            std::cout << "MyClass(int value) called" << value << std::endl;
        }

        void dosomething(){
            std::cout << "do something" << std::endl;
        }    
};

void funThattakesmyclass(MyClass obj){
    obj.dosomething();
}

int main(){
    //增加了explicit就会报错，因为这里int转换为了MyClass，添加explicit就禁止隐式转换
    funThattakesmyclass(5);
    return 0;
}