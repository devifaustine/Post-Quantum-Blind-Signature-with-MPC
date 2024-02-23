# benchmark the hash generation of shake256 with secure object

from shake import SHAKE
import mpyc.runtime as mpc
from time import *
import string

# number of times
n = 100