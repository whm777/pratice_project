#include <iostream>

template<typename T >
class My_shared_ptr
{
    private:
        T* ptr;
        size_t* count;

        static std::pair<T* , size_t *> createControlBlock(T* p){
            size_t *count = new size_t(1);
            return {p, count};
        }

        static void destroy(T* p , size_t * count ){
            delete p ;
            delete count;
        }

    public:
        //构造函数
        explicit My_shared_ptr(T* p = nullptr) : ptr(p ? createControlBlock(p).first : nullptr),
                                                   count(p ? createControlBlock(p).second : nullptr)
        {}

        //复制构造函数
        My_shared_ptr(const My_shared_ptr<T>& other) : ptr(other.ptr), count(other.count){
            if(count){
                ++(*count);
            }
        }

        //移动构造函数
        My_shared_ptr(My_shared_ptr<T>&& other) noexcept : ptr(other.ptr), count(other.count){
            other.ptr = nullptr;
            other.count = nullptr;
        }

        //赋值运算符
        My_shared_ptr<T>& operator=(const My_shared_ptr<T>& other){
            if(this != &other){
                if(--(*count) == 0){
                    destroy(ptr, count);
                }
                ptr = other.ptr;
                count = other.count;
                if(count){
                    ++(*count);
                }
            }
            return *this;
        }

        //移动赋值运算符
        My_shared_ptr<T>& operator=(My_shared_ptr<T>&& other) noexcept{
            if(this != &other){
                if(--(*count) == 0){
                    destroy(p, count);
                }
                ptr = other.ptr;
                count = other.count;
                other.ptr = nullptr;
                other.count = nullptr;
            }
            return *this;
        }
        //析构函数
        ~My_shared_ptr(){
            if(--(*count) == 0){
                destory(p , count);
            }
        }
        T& operator*() const(return *ptr;)
        T* operator->() const(return ptr;)

};

