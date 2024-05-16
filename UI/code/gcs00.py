import random
import string
import sm2
from gmssl.sm3 import sm3_kdf
from gmssl import sm4
import binascii
import socket
import threading
from typing import List
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# socket绑定的ip
socket_ip = ('0.0.0.0', 38806)

# 存储所有发现的UAV实例
available_uavs: List[tuple] = []

# 用于监听广播的Socket
broadcast_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
broadcast_listener.bind(('', 37020))

def listen_for_broadcasts():
    while True:
        data, addr = broadcast_listener.recvfrom(1024)
        message = data.decode()
        if message.startswith("UAV@"):
            ip_port = message.split("@")[1]
            ip, port = ip_port.split(":")
            port = int(port)
            uav_info = (ip, port)
            if uav_info not in available_uavs:
                available_uavs.append(uav_info)
                print(f"Discovered UAV at {ip}:{port}")

# 启动广播监听线程
broadcast_listener_thread = threading.Thread(target=listen_for_broadcasts)
broadcast_listener_thread.daemon = True
broadcast_listener_thread.start()

# 等待发现UAV实例
while not available_uavs:
    pass

# 打印所有发现的UAV实例
print("Available UAVs:")
for i, uav in enumerate(available_uavs):
    print(f"{i+1}. {uav[0]}:{uav[1]}")

# 让用户选择一个UAV实例进行连接
selected_uav_index = int(input("Enter the number of the UAV to connect: "))
selected_uav = available_uavs[selected_uav_index - 1]
print(selected_uav)

def send_heartbeat(sock):
    """发送心跳包，并根据服务器回应决定是否继续发送心跳包"""
    try:
        sock.sendall("heartbeat".encode())  # 发送心跳包
        data = sock.recv(1024).decode()  # 接收回复
        if data == "alive":
            print("服务器存活，将在10秒后再次发送心跳包")
            threading.Timer(10, send_heartbeat, [sock]).start()
        else:
            print("服务器响应异常，停止发送心跳包")
    except socket.error as e:
        print(f"连接异常，停止发送心跳包: {e}")
        sock.close()

# GCS程序
def GCS():
    global timer_running
    # 发送心跳包确认存活
    def client():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((selected_uav[0], selected_uav[1]))
        print("连接到无人机，发送心跳包检测无人机是否存活")
        s.sendall("heartbeat".encode())  # 发送心跳包
        data = s.recv(1024).decode()  # 接收回复
        if data == "alive":
            print("无人机存活，可以进行SM2密钥交换")
        return s

    s = client()

    # sm2密钥协商
    id_b = "42494C4C343536405941484F4F2E434F4D"
    entl_b = "0088"

    curve = sm2.Curve()

    user_b = sm2.Sm2KeyAgreement(curve, id_b, entl_b)

    p_b = user_b.curve.dot_to_bytes(user_b.pre_pub_key)
    r_b = user_b.curve.dot_to_bytes(user_b.tem_pub_key)
    z_b = user_b.id_auth_code

    # 获取用户B的公钥、身份认证码和消息的sm3哈希值
    user_a_data = sm2.send_user_b_data_get_user_a_data(p_b, r_b, z_b,
                                                       socket_ip)

    # 提取用户B的公钥、临时会话公钥和身份认证码
    p_a = user_a_data["p_a"]
    r_a = user_a_data["r_a"]
    z_a = user_a_data["z_a"]

    v_x, v_y = user_b.key_adgreement(p_a, r_a)

    k_a = sm3_kdf((v_x + v_y + z_a + z_b).encode(), user_b.klen)

    print("共享的密钥为：", k_a)

    # SM4加密函数
    def sm4_encrypt(key, data):
        if isinstance(key, str):
            key = key.encode()
        crypt_sm4 = sm4.CryptSM4()
        crypt_sm4.set_key(key[:16], sm4.SM4_ENCRYPT)
        encrypted_data = crypt_sm4.crypt_ecb(data.encode())
        return encrypted_data

    # AES加密函数
    def aes_encrypt(key, data):
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        iv = cipher.iv
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = iv + cipher.encrypt(padded_data)
        return encrypted_data

    # 注入噪声函数
    def inject_noise(ciphertext, noise_freq):
        noise_data = bytearray()
        for i, byte in enumerate(ciphertext):
            noise_data.append(byte)
            if (i + 1) % noise_freq == 0:
                noise = random.randint(0, 255)
                noise_data.append(noise)
        noise_data.append(noise_freq)
        return bytes(noise_data)

    # 生成随机字符串
    def generate_random_string(length):
        characters = string.ascii_letters + string.digits + string.punctuation + ' '
        random_string = ''.join(random.choice(characters) for i in range(length))
        return random_string

    # 发送虚假流量函数
    def send_fake_data():
        # 生成虚假流量
        fake_data = generate_random_string(random.randint(10, 100))
        noise_freq = random.randint(2, 8)
        send_encrypted_message(server_address[0], server_address[1], fake_data, k_a, encryption_algorithm, noise_freq)

    # 定时执行发送虚假流量函数
    def repeat_send_fake_data(interval):
        send_fake_data()
        send_timer = threading.Timer(interval, repeat_send_fake_data, [interval])
        # 定时发送虚假流量是否结束线程判断
        if timer_running:
            send_timer.start()
        else:
            send_timer.cancel()

    # 使用socket发送加密数据
    def send_encrypted_message(ip, port, message, key, algorithm, freq):
        if algorithm == "SM4":
            encrypted_message = b"SM4:" + sm4_encrypt(key, message)
        elif algorithm == "AES":
            encrypted_message = b"AES:" + aes_encrypt(key, message)
        else:
            print("Invalid encryption algorithm selected.")
            return

        # 使用binascii.hexlify转换为十六进制字符串并打印
        print("加密后的消息(hex)：", binascii.hexlify(encrypted_message).decode())
        if freq > 0:
            # 注入噪声65552566444+4545545456545
            encrypted_message_with_noise = inject_noise(encrypted_message, freq)
            encrypted_message_with_noise = b"noise:" + encrypted_message_with_noise
            # 使用binascii.hexlify转换为十六进制字符串并打印
            print("加密并注入噪声后的消息(hex)：", binascii.hexlify(encrypted_message_with_noise).decode())
        else:
            encrypted_message_with_noise = encrypted_message

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((ip, port))
            s.sendall(encrypted_message_with_noise)
            print("加密消息已发送")

    # 定义用户B的服务器地址和端口
    server_address = (selected_uav[0], selected_uav[1])

    # 让用户选择加密算法
    encryption_algorithm = input("请选择加密算法(SM4/AES): ")

    # 让用户选择是否使用固定噪声频率
    is_noise = input("请选择是否固定噪声频率(y/n)?")
    if is_noise == 'Y' or is_noise == 'y':
        # 让用户输入注入噪声频率，每noise_freq个字节注入一个噪声字节
        noise_freq = int(input("请输入噪声频率(>0整数，0即不注入噪声):"))
    else:
        is_noise = 'n'

    # 让用户选择发送虚假流量方式
    send_fake_data_type = input("请选择发送虚假流量方式(定时发送0，发送真实消息时发送1，两种都有2，都不用3):")
    if send_fake_data_type == '0' or send_fake_data_type == '2':
        send_freq = int(input("请输入定时发送虚假流量时间间隔(>0整数):"))
        timer_running = True
        # 每隔send_freq时间发送一个虚假流量，虚假流量一
        repeat_send_fake_data(send_freq)

    # 循环发送消息
    try:
        while True:
            message = input("请输入您想发送的消息（输入'exit'退出）：")
            if message == 'exit':
                timer_running = False
                break
            if is_noise == 'n':
                # 让用户输入注入噪声频率，每noise_freq个字节注入一个噪声字节
                noise_freq = int(input("请输入噪声频率(>0整数，0即不注入噪声):"))
            if send_fake_data_type == '0' or send_fake_data_type == '3':
                send_encrypted_message(server_address[0], server_address[1], message, k_a, encryption_algorithm,
                                       noise_freq)
            else:
                # 发送虚假流量和真实消息，虚假流量二
                rank = random.randint(0, 2)
                for i in range(3):  # 每次发送2个虚假数据，1个真实消息
                    if i == rank:
                        send_encrypted_message(server_address[0], server_address[1], message, k_a, encryption_algorithm,
                                               noise_freq)
                    else:
                        fake_data = generate_random_string(random.randint(10, 100))
                        send_encrypted_message(server_address[0], server_address[1], fake_data, k_a,
                                               encryption_algorithm, noise_freq)
    finally:
        s.close()

GCS()