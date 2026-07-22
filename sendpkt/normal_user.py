from ia_user import *
from ac_user import *
from sm_user import *
import argparse


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('User')
    parser.add_argument('Resource')
    parser.add_argument('ResourceEID')
    parser.add_argument('SendInterval')
    args=parser.parse_args()
    # user identity register
    ia_register(args.User)
    time.sleep(3)
    # user identity authen
    result=0
    while not result:
        result=ia_authen(args.User)
        time.sleep(3)
    # user EID register
    result=False
    while not result:
        result = sm_register('ur',args.User)
        time.sleep(3)
    # user access control
    result=False
    while not result:
        result = ac(args.User,args.Resource)
        time.sleep(3)
    # user normal communication
    data_len=[i for i in range(1,500)]
    length=len(data_len)
    random.shuffle(data_len)
    i=0
    while True:
        i=i//length
        data = ''.join(random.choices('''1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM)(*&^%$#@!~{}|<>?.,''',k=data_len[i]))
        send_data(12345,args.ResourceEID,12345,data)
        i+=1
        time.sleep(float(args.SendInterval))