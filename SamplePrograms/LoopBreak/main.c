#include <stdio.h>
int main() {
    int res = 0;
    int n = 10;
    for(int i = 0; i < n; i++){
        res++;
        if(i > (n - 5)){
            break;
        }
    }
    return 0;
}