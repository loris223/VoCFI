/*
This should pose challenge because of multiple
jumps to the same loop entry point.
*/
#include <stdio.h>
int main() {
    int n = 0;
    int i = 5;
    while(i > n || i == 0){
        i--;
    }
    return 0;
}