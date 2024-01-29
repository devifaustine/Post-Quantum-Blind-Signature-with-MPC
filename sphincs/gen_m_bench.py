# Generates messages for the benchmark in bytestring
import argparse
import random
import string

# set log variable to true for logging
log = False

def digest(list):
    """
    prints out the list to be used as a bash array
    :param list: list of objects
    :return: none 
    """
    for i in list:
        print(i)

def xprint(string):
    if log:
        print(string)

# _________________________________________________________________________________________________


def gen_message(n=1, size=0):
    """
    generate n message(s)
    :param n: the number of messages generated
    :param size: maximum size of the message (default = 70)
    :return: message(s) printed out
    """

    messages = []

    # generating random messages
    for i in range(n):
        if size == 0:
            length = random.randint(1, 70)
        else:
            length = random.randint(1, size)
        message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
        # message is originally string, but converted into bytes
        # TODO: check if converting to bytes is necessary for signing process!
        #messages.append(bytes(message, 'ascii'))
        messages.append(message)

    # messages need to be printed out - for bash variable - therefore digest
    digest(messages)

# _________________________________________________________________________________________________

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', type=int, metavar='N',
                        help='number of times N (default 1) to create the key pairs')
    parser.add_argument('-s', type=int, metavar='S',
                        help='maximum length of the message to be generated')
    parser.set_defaults(n=1, s=0)
    args = parser.parse_args()
    gen_message(args.n, args.s)