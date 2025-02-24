import math
import multiprocessing
import os
import time
import random
import csv
import psutil
from multiprocessing import Pool

global user_id_list, gateway, gacsf, gacc

time_type_list = ['INT', None]
user_type_list = ['RU', 'PU', 'Admin']
admin_attack_type_list = ['NAcc', 'RS', 'ATK', 'RS+ATK', 'RS+ATK(2)']
attack_type_list = ['NAcc', 'RS', 'ATK', 'PE', 'RS+ATK', 'RS+PE', 'ATK+PE', 'RS+ATK+PE', 'RS+ATK+PE(2)']
delta = {"P_AS": 0.012, "P_ACS": 0.945, "P_LAF": 0.031, "f_RL1": 0.012}
sigma = {"P_AF": 0.036, "P_ACF": 0.017, "P_SAC": 0.039, "f_RL2": 0.004, "MTP_index": 0.903}


# 计算用户信誉值
def calculate_reputation(user, gateway):
    # 计算各概率，确保除法结果是浮点数
    if user["AC"] >= 0 and gateway["GAC"] >= 0:
        P_AS = (float(user["ASF"]) / float(user["AC"])) * (float(gateway["GASF"]) / float(gateway["GAC"]))
    else:
        raise ValueError("Invalid values for AC or GAC")

    if user["ACC"] >= 0 and gateway["GACC"] >= 0:
        P_ACS = (float(user["ACSF"]) / float(user["ACC"])) * (float(gateway["GACSF"]) / float(gateway["GACC"]))
        P_LAF = float(user["LAC"]) / float(user["ACC"])
    else:
        raise ValueError("Invalid values for ACC or GACC")

    if user["CARL"] <= user["CAPL"]:
        f_RL = 1
    elif user["CAPL"] > 0:
        f_RL = max(float(user["CAPL"]) / (float(user["CARL"]) - float(user["CAPL"])), 2)
    else:
        f_RL = 1

    # 判断 ACC-ACSF 是否超过阈值 n，调整信誉值
    if (user["ACC"] - user["ACSF"]) > 1 or (user["SACF"] / user["ACF"] > 0.05) or user["MTP"] > 0.1:
        reputation_penalty = 3
    else:
        reputation_penalty = 1

    # 联合概率
    P_X_given_theta_plus = (
            P_AS * delta["P_AS"] + P_ACS * delta["P_ACS"] + P_LAF * delta["P_LAF"] + f_RL * delta["f_RL1"]
    )

    # 先验概率
    P_X = (
            (float(gateway["GASF"]) / float(gateway["GAC"]))
            * (float(gateway["GACSF"]) / float(gateway["GACC"]))
            * f_RL
    )
    P_theta_plus = gateway["GRV"] if user["HBHS"] == 0 else user["HBHS"]

    # 信誉值
    R_U_plus = (P_X_given_theta_plus * P_theta_plus) / (P_X * reputation_penalty)
    R_U_plus = 1 / (1 + math.exp(-R_U_plus))

    return R_U_plus


# 计算用户风险值
def calculate_risk(user, gateway):
    # 计算各概率，确保除法结果是浮点数
    P_AF = (1 - float(user["ASF"]) / float(user["AC"])) if user["AC"] > 0 else 0
    P_ACF = (1 - float(user["ACSF"]) / float(user["ACC"])) if user["ACC"] > 0 else 0

    if user["CARL"] <= user["CAPL"]:
        f_RL = 1
    elif user["CAPL"] > 0:
        f_RL = max(float(user["CAPL"]) / (float(user["CARL"]) - float(user["CAPL"])), 2)
    else:
        f_RL = 1

    P_SAC = user["SACF"] / user["ACF"] if user["ACF"] > 0 else 0

    # 判断 ASF-ACSF 和 ACC-ACSF 是否超过阈值 n，调整风险值
    risk_boost = 0.5 if (
            (user["ACC"] - user["ACSF"]) > 1
            or P_SAC > 0.05
            or user["MTP"] > 0.1
    ) else 1

    # 联合概率
    P_X_given_theta_minus = (
            sigma["P_AF"] * P_AF
            + sigma["P_ACF"] * P_ACF
            + sigma["f_RL2"] * f_RL
            + sigma["P_SAC"] * P_SAC
            + sigma["MTP_index"] * user["MTP"]
    )

    # 先验概率
    P_X = (
            (float(gateway["GASF"]) / float(gateway["GAC"]))
            * (float(gateway["GACSF"]) / float(gateway["GACC"]))
            * f_RL
    )
    P_theta_minus = gateway["GRR"] if user["HBHR"] == 0 else user["HBHR"]

    # 风险值
    R_U_minus = (P_X_given_theta_minus * P_theta_minus) / (P_X * risk_boost)
    R_U_minus = 1 / (1 + math.exp(-R_U_minus))

    return R_U_minus


# 计算用户行为分数
def calculate_behavior_scores(user, reputations, risks, alpha=0.5, beta=0.5):
    scores = (alpha * reputations - beta * risks) * 10
    scores = max(0.0, min(scores, 1.0))
    smoothed_behavior_score = 0.7 * user["behavior_score"] + 0.3 * scores
    # print("behavior scores:", smoothed_behavior_score)
    return smoothed_behavior_score


# 计算网关信誉值和风险值
def calculate_gateway_values(user, gateway, gateway_reputation_old, gateway_risk_old):
    # 原始计算
    new_reputation = (user["behavior_score"] + (gateway["User_Num"] - 1) * gateway["GRV"]) / gateway["User_Num"]
    new_risk = (-user["behavior_score"] + (gateway["User_Num"] - 1) * gateway["GRR"]) / gateway["User_Num"]

    reputation_diff = new_reputation - gateway_reputation_old
    risk_diff = new_risk - gateway_risk_old

    if new_reputation - gateway_reputation_old < -0.01:
        new_reputation = new_reputation - 0.2
    if new_risk - gateway_risk_old > 0.01:
        new_risk = new_risk + 0.2

    # 限制变化幅度
    max_change = 0.2
    reputation_diff = new_reputation - gateway["GRV"]

    if abs(reputation_diff) > max_change:
        new_reputation = gateway["GRV"] + max_change * (1 if reputation_diff > 0 else -1)

    new_reputation = 0.7 * gateway["GRV"] + 0.3 * new_reputation
    new_risk = 0.7 * gateway["GRR"] + 0.3 * new_risk

    # 使用指数函数限制范围
    reputation = 1 / (1 + math.exp(-min(new_reputation, 1)))
    risk = 0.5 / (1 + math.exp(-max(new_risk, -1)))
    return reputation, risk, reputation_diff, risk_diff


# 更新用户访问等级
def update_capl(user, behavior_score_old):
    # 确定当前 CAPL 的范围区间
    capl_ranges = [(0, 9), (10, 19), (20, 29)]
    for a, b in capl_ranges:
        if a <= user["CAPL"] <= b:
            break
    else:
        print("CAPL value error: out of range")
        return user["CAPL"]  # 返回当前权限值，防止逻辑中断

    # 计算评分变化
    behavior_score_change = user["behavior_score"] - behavior_score_old
    # print('user score:', user['behavior_score'])
    # print('behavior score change:', behavior_score_change)

    # 根据评分变化调整权限
    if abs(behavior_score_change) >= 0.05:
        AL_new = user["CAPL"] + 1 if behavior_score_change > 0 else user["CAPL"] - 1
    elif math.floor(user["CARL"] / 10) > math.floor(user["CAPL"] / 10):
        AL_new = user["CAPL"] - 10
    else:
        AL_new = user["CAPL"]

    # 检查其他调整条件
    if user["MTP"] > 0.1:
        AL_new -= 1
    if user["SACF"] / user["ACF"] > 0.05 and user["SACF"] != 1:
        AL_new -= 1

    # 限制权限级别在当前区间范围内
    return max(a, min(AL_new, b))


def update_common_attributes(user, gateway):
    behavior_score_old = user['behavior_score']
    gateway_reputation_old = gateway['GRV']
    gateway_risk_old = gateway["GRR"]

    # 更新网关值

    gateway["GACC"] = gateway["GACC"] + 1

    user_reputation = calculate_reputation(user, gateway)  # 计算用户信誉
    user_risk = calculate_risk(user, gateway)  # 计算用户风险
    user_bs_new = calculate_behavior_scores(user, user_reputation, user_risk)  # 计算用户行为分数

    user["HBHS"] = user_reputation
    user["HBHR"] = user_risk
    user['behavior_score'] = user_bs_new  # 更新用户行为分数
    user['CAPL'] = update_capl(user, behavior_score_old)  # 更新用户等级
    user["AS_TS"] = int(time.perf_counter() * 1e9)
    user["ACC"] += 1
    user["FACF"] = user["ACC"] - user["ACSF"]
    user["ACF"] = user["ACC"] / (user["AS_TS"] - user["AUTH_TS"])
    user["SACF"] = (user["ACSF"] - user["LAC"]) / (user["AS_TS"] - user["AUTH_TS"])

    gateway["GRV"], gateway["GRR"], gateway['GRV_diff'], gateway['GRR_diff'] = calculate_gateway_values(user, gateway,
                                                                                                        gateway_reputation_old,
                                                                                                        gateway_risk_old)  # 计算网关信誉和风险
    return user, gateway


def update_different_parts(user, gateway):
    # 根据条件更新用户状态
    if math.floor(user["CAPL"] / 10) < math.floor(user["CARL"] / 10) or user["MTP"] >= 0.3 or user["ACF"] > 100 * 1e9:
        user["ACF"] = user["ACC"] / (user["AS_TS"] - user["AUTH_TS"])
        user, gateway = update_common_attributes(user, gateway)

    else:
        user["ACSF"] = user["ACSF"] + 1
        if user["CAPL"] >= user["CARL"]:
            user["LAC"] += 1

        gateway["GACSF"] += 1
        user, gateway = update_common_attributes(user, gateway)

    return user, gateway


# 设置初始用户和网关参数
def init_user_value(capl, gateway):
    user_init = {"uid": random.randint(1, 10000000), "AC": 1, "ASF": 1, "FAF": 0, "AUTH_TS": 0, "ACC": 0, "ACSF": 0,
                 "FACF": 0, "AS_TS": 0, "CAPL": capl, "CARL": random.randint(0, capl - 5), "LAC": 1, "ACF": 0,
                 "SACF": 0, "MTP": 0, "HBHS": 0.66, "HBHR": 0.5, "behavior_score": 0.81}
    return user_init


# 保存多个字典到CSV
def save_dicts_to_csv(lock, filename, *dicts):
    # 获取所有字典的字段名，并去重
    fieldnames = []
    for dictionary in dicts:
        fieldnames.extend(dictionary.keys())

    # # 去重字段名
    # fieldnames = list(set(fieldnames))

    # 检查文件是否存在
    file_exists = os.path.exists(filename)

    # 打开CSV文件，决定是写入新文件还是追加数据
    with lock:
        with open(filename, mode="a", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            # 如果文件不存在，写入表头
            if not file_exists:
                writer.writeheader()

            # 合并所有字典数据并写入
            merged_data = {}
            for dictionary in dicts:
                merged_data.update(dictionary)

            writer.writerow(merged_data)


def get_attack_rounds(k, time_type, attack_type):
    if time_type == "INT":
        attack_rounds = [20, 23, 26, 29]
    elif time_type is None:
        if attack_type == 'RS+ATK+PE(2)':
            attack_rounds = list(range(18 + attack_type_list.index(attack_type), k, 1))
        else:
            attack_rounds = list(range(19 + attack_type_list.index(attack_type), k, 1))
    else:
        attack_rounds = None
        print(time_type, 'error2')
    return attack_rounds


def user_access(user_type, time_type, attack_type, gateway, lock, user_id_list, user_num, attack_index, k):
    acc_rounds, acc_round = 100, 0
    user_type_config = {'RU': 5, 'PU': 15, 'Admin': 25}
    capl = user_type_config.get(user_type, None)
    if capl is None:
        print(user_type, 'error1')
        return None, None
    user = init_user_value(capl, gateway)
    user["AUTH_TS"] = int(time.perf_counter() * 1e9)

    if user['uid'] not in user_id_list:
        user_id_list.append(user['uid'])
    batch_data = []
    attack_rounds = get_attack_rounds(acc_rounds, time_type, attack_type)
    print(attack_rounds, time_type, attack_type)
    while acc_rounds > acc_round:
        if user['behavior_score']<0.7:
            break
        gateway["User_Num"] = len(user_id_list)
        gateway["GASF"] = len(user_id_list)
        gateway["GAC"] = len(user_id_list)
        user['each_ts'] = int(time.perf_counter() * 1e9)
        used_memory, memory_usage_percent, cpu_usage = get_system_usage()
        usage_dict = {'used_memory': used_memory, 'memory_usage_percent': memory_usage_percent, 'cpu_usage': cpu_usage}

        # save_dicts_to_csv(lock, f"D:\\01_08_零信任网元\\数据处理\\gateway_score_{user_num}_user.csv", user, gateway,
        #                   usage_dict)
        save_dicts_to_csv(lock,
                          f"D:\\01_08_零信任网元\\数据处理\\网关信誉和风险值变化\\gateway_score_detect_{user_num}_INT_{attack_index}_{k}user.csv",
                          gateway, user, usage_dict)

        # # 将当前用户和网关的数据添加到批量数据中
        # batch_data.append((user, gateway, usage_dict))
        #
        # # 每 batch_size 次保存一次数据
        # if len(batch_data) >= 25:
        #     with lock:
        #         # 批量保存到 CSV 文件
        #         for user_data, gateway_data, usage_data in batch_data:
        #             save_dicts_to_csv(lock, f"D:\\01_08_零信任网元\\数据处理\\gateway_score_{user_num}_user.csv",
        #                               user_data, gateway_data, usage_data)
        #             time.sleep(1)
        # 清空批量数据缓冲区
        # if time_type is None:
        #     save_user_and_gateway_to_csv(user, gateway, delta, sigma,
        #                                  "D:\\01_08_零信任网元\\数据处理\\" + user_type + " " + attack_type + ".csv")
        # else:
        #     save_user_and_gateway_to_csv(user, gateway, delta, sigma,
        #                                  "D:\\01_08_零信任网元\\数据处理\\" + time_type + " " + user_type + " " + attack_type + ".csv")

        if acc_round in attack_rounds:
            user = attack(acc_round, user, attack_type)
        else:
            user["CARL"] = random.randint(0, user["CAPL"])

        if user['ACC'] == 0:
            user = {"uid": user["uid"], "AC": 1, "ASF": 1, "FAF": 0, "AUTH_TS": 0, "ACC": 1, "ACSF": 1, "FACF": 0,
                    "AS_TS": 1, "CAPL": user["CAPL"], "CARL": user["CARL"], "LAC": 1, "ACF": 1.0, "SACF": 1.0, "MTP": 0,
                    "HBHS": 0.66, "HBHR": 0.5, "behavior_score": 0.8}
            user, gateway = update_different_parts(user, gateway)
        else:
            user, gateway = update_different_parts(user, gateway)
        acc_round += 1
    return user, gateway


# 敏感访问
def sensitive_resource(user):
    upper_bound = min((user["CAPL"] // 10 + 1) * 10 - 1, 29)
    user["CARL"] = random.randint(user["CAPL"] + 1, upper_bound)
    return user


# 越级访问
def leapfrog(user):
    if user["CAPL"] < 10:
        user["CARL"] = random.randint(10, 29)  # 如果 CAPL 在 0 到 9 之间，访问 10 到 29
    elif user["CAPL"] < 20:
        user["CARL"] = random.randint(20, 29)  # 如果 CAPL 在 10 到 19 之间，访问 20 到 29
    return user


# 越级访问和敏感信息访问
def sens_and_leap(user):
    # 敏感和越级访问
    if user["CAPL"] < 10:
        user["CARL"] = random.randint(user["CAPL"] + 1, 29)  # 如果 CAPL 在 0 到 9 之间，访问 10 到 29
    elif user["CAPL"] < 20:
        user["CARL"] = random.randint(user["CAPL"] + 1, 29)  # 如果 CAPL 在 10 到 19 之间，访问 20 到 29
    return user


# ddos攻击
def ddos_attack(user):
    # 攻击
    user["MTP"] = 1
    return user


def attack(i, user1, attack_type):
    # 定义攻击类型与对应的处理函数
    attack_map = {
        'NAcc': lambda: user1.update({"CARL": random.randint(0, user1["CAPL"])}),
        'RS': lambda: sensitive_resource(user1),
        'ATK': lambda: ddos_attack(user1),
        'PE': lambda: leapfrog(user1),
        'RS+ATK': lambda: ddos_attack(sensitive_resource(user1)),
        'RS+PE': lambda: sens_and_leap(user1),
        'ATK+PE': lambda: leapfrog(ddos_attack(user1)),
        'RS+ATK+PE': lambda: sens_and_leap(ddos_attack(user1)),
        'RS+ATK+PE(2)': lambda: ddos_attack(sens_and_leap(user1)) if i in [20, 26] else ddos_attack(user1) if i in [23,
                                                                                                                    29] else user1,
        'RS+ATK(2)': lambda: sensitive_resource(user1) if i in [20, 26] else ddos_attack(user1) if i in [23,
                                                                                                         29] else user1
    }

    # 调用对应的攻击类型处理函数
    if attack_type in attack_map:
        attack_map[attack_type]()
        return user1  # 执行映射到的攻击操作
    else:
        print(attack_type, 'error3')  # 错误处理
        return None


def get_system_usage():
    # 获取 CPU 使用率
    cpu_usage = psutil.cpu_percent(interval=0)  # 1秒间隔

    # 获取内存使用情况
    memory = psutil.virtual_memory()

    # 已用内存
    used_memory = memory.used / (1024 ** 3)  # 转换为 GB
    # 内存使用率
    memory_usage_percent = memory.percent

    return used_memory, memory_usage_percent, cpu_usage


def main(attack_index, attack_user_round, k):
    # user_begin = {'user_type': 'RU', 'user_attack_type': 'NAcc'}

    # 创建一个 Manager 实例
    manager = multiprocessing.Manager()
    # 创建一个锁
    lock = manager.Lock()

    # # 创建一个全局共享字典
    gateway = manager.dict(
        {"GASF": 1, "GAC": 1, "GACSF": 0, "GACC": 0, "User_Num": 0, "GRV": 0.66, "GRR": 0.28, "GRV_diff": 0,
         'GRR_diff': 0})
    user_id_list = manager.list([])

    processes = []
    ts1 = int(time.perf_counter() * 1e9)
    user_num = 10

    for i in range(user_num):  # 创建 10 个进程
        if i in attack_user_round:

            process = multiprocessing.Process(target=user_access,
                                              args=(
                                                  random.choice(user_type_list), 'INT', attack_index, gateway, lock,
                                                  user_id_list, user_num, attack_index, k))
        # elif i == 10:
        #     process = multiprocessing.Process(target=user_access,
        #                                       args=(
        #                                           random.choice(user_type_list), 'INT', 'RS', gateway, lock,
        #                                           user_id_list, user_num))
        #
        # elif i == 20:
        #     process = multiprocessing.Process(target=user_access,
        #                                       args=(
        #                                           random.choice(user_type_list), 'INT', 'PE', gateway, lock,
        #                                           user_id_list, user_num))
        else:
            process = multiprocessing.Process(target=user_access,
                                              args=(
                                                  random.choice(user_type_list), None, 'NAcc', gateway, lock,
                                                  user_id_list, user_num, attack_index, k))
        processes.append(process)
        process.start()

        # 等待所有进程完成
    for process in processes:
        process.join()
    # # 创建进程池，使用apply_async提交任务
    # with multiprocessing.Pool(processes=10) as pool:  # 假设使用100个进程
    #     for i in range(user_num):
    #         if i >50:
    #             # 异步提交任务
    #             result = pool.apply_async(user_access,
    #                                       args=('PU', None, 'PE', gateway, lock, user_id_list,
    #                                             user_num))
    #         else:
    #             # 异步提交任务
    #             result = pool.apply_async(user_access,
    #                                       args=(
    #                                           random.choice(user_type_list), None, 'NAcc', gateway, lock, user_id_list,
    #                                           user_num))
    #
    #     # 关闭进程池并等待所有任务完成
    #     pool.close()
    #     pool.join()

    print(user_id_list)
    print("delay", int(time.perf_counter() * 1e9) - ts1)


if __name__ == '__main__':
    main('RS', [5], 1)
    time.sleep(1)
    main('ATK', [5], 1)
    time.sleep(1)
    main('PE', [5], 1)
    time.sleep(1)
    main('RS+ATK+PE', [5], 1)
    time.sleep(1)
    main('RS', [5, 6, 7, 8, 9], 5)
    time.sleep(1)
    main('ATK', [5, 6, 7, 8, 9], 5)
    time.sleep(1)
    main('PE', [5, 6, 7, 8, 9], 5)
    time.sleep(1)
    main('RS+ATK+PE', [5, 6, 7, 8, 9], 5)
