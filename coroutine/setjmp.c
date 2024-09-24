#include <stdio.h>
#include <setjmp.h>

jmp_buf context1;

void trigjump(){
    printf("trigjump\n");
    longjmp(context1 , 1);
}

int main(){

    if(setjmp(context1) == 0){
        printf ("setjmp\n");
        trigjump();
        printf ("after trigjump\n");
    }
    else{
        printf ("longjmp\n");
    }


    return 0;
}