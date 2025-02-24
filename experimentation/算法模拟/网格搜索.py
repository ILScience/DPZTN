from soft_score import *
import numpy as np
import itertools
import gc


def grid_search(user_data, gateway, delta_range, sigma_range, n):
    best_delta = None
    best_sigma = None
    best_score_diff = float('inf')
    results = []
    # 生成所有delta和sigma的组合
    delta_combinations = [
        delta for delta in itertools.product(*delta_range)
        if abs(sum(delta) - 1) < 1e-6  # 加入和为1的约束
    ]
    for delta in delta_combinations:

        sigma_combinations = [
            sigma for sigma in itertools.product(*sigma_range)
            if abs(sum(sigma) - 1) < 1e-6  # 加入和为1的约束
        ]
        for sigma in sigma_combinations:
            user_data_copy = user_data.copy()
            gateway_copy = gateway.copy()
            delta_dict = {"P_AS": delta[0], "P_ACS": delta[1], "P_LAF": delta[2], "f_RL1": delta[3]}
            sigma_dict = {"P_AF": sigma[0], "P_ACF": sigma[1], "P_SAC": sigma[2], "f_RL": sigma[3], "MTP": sigma[4]}

            # 执行一次攻击或越权访问
            user1, _, score_diff = user_access(user_data_copy, gateway_copy, delta_dict, sigma_dict, n)

            # 如果当前的行为分数差异更大，则更新最优解
            if score_diff < best_score_diff:
                print(delta)
                print(sigma)
                print(score_diff)
                best_score_diff = score_diff
                best_delta = delta
                best_sigma = sigma
                # 将当前结果记录到内存中
            save_user_and_gateway_to_csv(user1, delta_dict, sigma_dict,
                                         {"score_diff": score_diff, "best_score_diff": best_score_diff},
                                         filename="网格搜索.csv")
        # 显式释放临时对象以减少内存占用
        del user_data_copy, gateway_copy, delta_dict, sigma_dict
        gc.collect()

    return best_delta, best_sigma, best_score_diff


# 初始用户值
ac, asf = 1, 1
acc, acsf = 1, 1
auth_end_time = 0
acc_time = 1
lac = 1
capl = 15
carl = random.randint(0, capl - 5)
mtp = 0
hbhs = 1
hbhr = 0
user_data = {"AC": ac, "ASF": asf, "FAF": (ac - asf), "AUTH_TS": auth_end_time, "ACC": acc, "ACSF": acsf,
             "FACF": (acc - acsf), "AS_TS": acc_time, "CAPL": capl, "CARL": carl,
             "LAC": lac, "ACF": acc / (acc_time - auth_end_time), "SACF": acsf / (acc_time - auth_end_time),
             "MTP": mtp, "HBHS": hbhs, "HBHR": hbhr, "behavior_score": 1}
gasf = 1
gac = 1
gacsf = 1
gacc = 1
grv = 1
grr = 0

# 初始网关值
gateway = {"GASF": gasf, "GAC": gac, "GACSF": gacsf, "GACC": gacc, "User_Num": 1, "GRV": grv, "GRR": grr}

# 定义delta和sigma的搜索范围
delta_range = [np.arange(0.05, 0.9, 0.05).tolist(), np.arange(0.05, 0.9, 0.05).tolist(),
               np.arange(0.05, 0.9, 0.05).tolist(), np.arange(0.05, 0.9, 0.05).tolist()]
sigma_range = [np.arange(0.05, 0.85, 0.05).tolist(), np.arange(0.05, 0.85, 0.05).tolist(),
               np.arange(0.05, 0.85, 0.05).tolist(), np.arange(0.05, 0.85, 0.05).tolist(),
               np.arange(0.05, 0.85, 0.05).tolist()]

# 网格搜索
best_delta, best_sigma, best_score_diff = grid_search(user_data, gateway, delta_range, sigma_range, 3)

print(f"Best Delta: {best_delta}")
print(f"Best Sigma: {best_sigma}")
print(f"Best Score: {best_score_diff}")
