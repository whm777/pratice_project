#include <iostream>

/*
unique_ptr 实现原理：
1. 禁止拷贝构造和拷贝赋值
2. 禁止移动构造和移动赋值


    unique_ptr表示对对象的独占所有权。
    在同一时间内，只能有一个unique_ptr指向一个给定的对象。
    当unique_ptr被销毁时（例如，离开作用域），它所指向的对象也会被自动删除。
    unique_ptr不能复制，但可以移动。
    
    适用于单个对象的动态内存管理，确保资源不被意外共享或泄露。

*/

template<typename T>
class My_unique_ptr{
private:
    T* ptr;

    //禁止拷贝构造和拷贝赋值
    //这里的delete是一种特殊的用法，称为删除函数，其在c++11后引入。用于显示禁止某个成员函数的生成和使用。
    //如果发现有友元函数或者其他成员函数调用标记为delete的函数，编译器就会报错。
    //虽然private可以限制外部直接访问该函数，但是友元或者模板特化可以间接访问private成员函数。
    My_unique_ptr(const My_unique_ptr&) = delete;
    My_unique_ptr& operator=(const My_unique_ptr&) = delete;

public:
    My_unique_ptr() : ptr(nullptr){}
    explicit My_unique_ptr(T *p) : ptr(p) {}
    //noexcept是c++11引入的一个关键字，用于保证函数不会抛出任何异常
    My_unique_ptr(My_unique_ptr&& other) noexcept : ptr(other.ptr){
        other.ptr = nullptr;
    }
    My_unique_ptr& operator=(My_unique_ptr&& other) noexcept{
        if(this != &other){
            delete ptr;
            ptr = other.ptr;
            other.ptr = nullptr;
        }
        return *this;
    }

    ~My_unique_ptr(){
        delete ptr;
    }

    //访问指针指向的值
    T& operator*() const{
        assert(ptr != nullptr);
        return *ptr;
    }

    //访问指针
    T* opereator->() const {
        assert(ptr != nullptr);
        return ptr;
    }

    //重置指针
    void reset(T* p = nullptr){
        delete ptr;
        ptr=p;
    }

    //访问原始指针
    T* get() const{
        return ptr;
    }

    bool emptr() const{
        return ptr == nullptr;
    }

    explicit operator bool() const{
        return ptr == nullptr;
    }

    


};