#!/usr/bin/python3

import math
import scipy
from scipy import constants

#just multiply each place by phi^place value?
def golden_to_hex(num) :
    place = 0
    result = 0
    while True :
        if num == 0 :
            break
        if num % 10 == 1 :
            result += scipy.constants.golden ** place
        num /= 10
        ++place
    return result

result = golden_to_hex(1)
print("correct? " + str(result))
