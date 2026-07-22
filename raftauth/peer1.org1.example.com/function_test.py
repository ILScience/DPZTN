from ac_user import *
from ia_user import *
from sm_user import *
import argparse
import time
import threading
parser=argparse.ArgumentParser()
parser.add_argument('function')
parser.add_argument('arguments')
args=parser.parse_args()

if args.function=='ac':
    user,resource,action=args.arguments.split('---')
    ac(user,resource,action)
elif args.function=='resource_policy':
    arguments=args.arguments.split('---')
    arguments='++++++'.join(arguments)
    resource_policy(arguments)
elif args.function=='ia_register':
    user,sqn,k,role,cluster,priviledge=args.arguments.split('---')
    ia_register(user,sqn,k,role,cluster,priviledge)
elif args.function=='ia_authen':
    user,sqn,k=args.arguments.split('---')
    ia_authen(user,sqn,k)
elif args.function=='sm_register':
    flag,user=args.arguments.split('---')
    sm_register(flag,user)
elif args.function=='send_data':
    counts,t,my_port, her_EID, her_port, data=args.arguments.split('---')
    for _ in range(int(counts)):
        send_data(my_port, her_EID, her_port, data)
        time.sleep(int(t))
elif args.function=='recv_data':
    t1 = threading.Thread(target=recv_data, args=())
    t2 = threading.Thread(target=repeat, args=())
    t1.start()
    t2.start()
else:
    print('参数错误！')
