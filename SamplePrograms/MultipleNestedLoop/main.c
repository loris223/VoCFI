#include <stdio.h>
int main() {
    int n = 5;
    int m = 10;
    int res = 0;
    for(int i = 0; i < n; i++){
        for(int j = 0; j < m; j++){
            res++;
        }
        for(int j = i; j < m; j++){
            res++;
        }
    }
    return 0;
}