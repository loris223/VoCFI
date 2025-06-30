#include <stdio.h>
int main() {
    int p = 25;
    int k = 35;
    if(p < k){
        if(k < 20){
            p += 10;
        }
        else{
            k -= 20;
        }
    }
    else{
        p = k;
    }
    return 0;
}