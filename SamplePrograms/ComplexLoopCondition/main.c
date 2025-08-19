/*
This should pose challenge because of multiple
jumps to the same loop entry point.
*/
#include <stdio.h>
int main() {
    int low = -10;
    int high = +10;
    int i = 0;
    while(i > low && i < high){
        i++;
        if(i == high){
            i = low;
        }
    }
    return 0;
}