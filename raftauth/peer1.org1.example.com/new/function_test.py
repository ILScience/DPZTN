#from ac_user import *
from ia_user import *
#from sm_user import *
import argparse
import time
import threading
parser=argparse.ArgumentParser()
parser.add_argument('function')
parser.add_argument('arguments')
args=parser.parse_args()

if args.function=='ia_register':
    user,sqn,k,role,cluster,priviledge=args.arguments.split('---')
    ia_register(user,sqn,k,role,cluster,priviledge)
elif args.function=='ia_authen':
    user,sqn,k=args.arguments.split('---')
    ia_authen(user,sqn,k)
else:
    print('参数错误！')
