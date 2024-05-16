import sm2
from gmssl.sm3 import sm3_kdf
from gmssl import sm4
import binascii
import socket
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 用户B的ip
server_address = ("127.0.0.1", 38806)

# 广播Socket
broadcast_socket = None

# 使用socket_ip启动服务监听
socket_ip = ('127.0.0.1', 38802)

def broadcast_server_info():
    global broadcast_socket
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        message = f"UAV@{socket_ip[0]}:{socket_ip[1]}".encode()
        broadcast_socket.sendto(message, ('<broadcast>', 37020))
        print(f"Broadcasted: {message.decode()}")
        threading.Event().wait(5.0)  # 每5秒广播一次


# 启动广播线程
broadcast_thread = threading.Thread(target=broadcast_server_info)
broadcast_thread.daemon = True
broadcast_thread.start()

# 发送心跳包存活
def send_heartbeat_response(conn):
    """定时发送心跳响应给用户A"""
    try:
        conn.sendall("alive".encode())  # 发送心跳响应
    except (ConnectionAbortedError, ConnectionResetError):
        print("连接已关闭，停止发送心跳响应")
    except Exception as e:
        print(f"发送心跳响应异常: {e}")


# 接收心跳包证明自身存活，并定时回复心跳包
def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 38802))
        s.listen()
        print("无人机启动，等待地面控制中心连接...")
        conn, addr = s.accept()
        with conn:
            print(f"无人机{addr}已连接到地面控制中心")
            data = conn.recv(1024).decode()  # 接收消息
            if data == "heartbeat":
                print("收到心跳包，回复地面控制中心存活确认")
                send_heartbeat_response(conn)  # 定时发送心跳响应


server()

"""
sm2密钥交换
"""
# 用户A的身份码及其长度
id_a = "414C494345313233405941484F4F2E434F4D"
entl_a = "0090"

curve = sm2.Curve()
user_a = sm2.Sm2KeyAgreement(curve, id_a, entl_a)

p_a = user_a.curve.dot_to_bytes(user_a.pre_pub_key)
r_a = user_a.curve.dot_to_bytes(user_a.tem_pub_key)
z_a = user_a.id_auth_code

# 获取用户B的公钥、身份认证码和消息的sm3哈希值
user_b_data = sm2.send_user_a_data_get_user_b_data(p_a, r_a, z_a,
                                                   server_address)

# 提取用户B的公钥、临时会话公钥和身份认证码
p_b = user_b_data["p_b"]
r_b = user_b_data["r_b"]
z_b = user_b_data["z_b"]

v_x, v_y = user_a.key_adgreement(p_b, r_b)

k_a = sm3_kdf((v_x + v_y + z_a + z_b).encode(), user_a.klen)
print("共享的密钥为：", k_a)


def sm4_decrypt(key, encrypted_data):
    if isinstance(key, str):
        key = key.encode()
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(key[:16], sm4.SM4_DECRYPT)
    decrypted_data = crypt_sm4.crypt_ecb(encrypted_data)
    return decrypted_data.decode()

def aes_decrypt(key, encrypted_data):
    iv = encrypted_data[:AES.block_size]
    cipher_text = encrypted_data[AES.block_size:]

    cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(cipher_text)
    decrypted_data = unpad(padded_data, AES.block_size)
    return decrypted_data.decode()

# 去除噪声函数
def remove_noise(ciphertext_with_noise):
    noise_freq = ciphertext_with_noise[len(ciphertext_with_noise) - 1]
    decoded = bytearray()
    i, j = 0, 0
    while i < len(ciphertext_with_noise) - 1:
        if i > 0 and (i - j) % ((j+1) * noise_freq) == 0:
            i += 1
            j += 1
        else:
            decoded.append(ciphertext_with_noise[i])
            i += 1
    return bytes(decoded)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', 38802))
    s.listen()
    print("等待地面站连接...")
    while True:
        conn, addr = s.accept()
        print(f"无人机{addr}已连接到地面控制中心")

        while True:
            try:
                encrypted_message_with_noise = conn.recv(1024)  # 接收加密消息
            except ConnectionAbortedError:
                print("连接已被中止")
                break  # 连接已中止,退出循环

            if not encrypted_message_with_noise:
                break  # 如果收到空数据,说明连接已断开

            # 使用binascii.hexlify转换为十六进制字符串并打印
            print("接收到的加密消息(hex)：", binascii.hexlify(encrypted_message_with_noise).decode())

            if encrypted_message_with_noise.startswith(b"noise:"):
                encrypted_message_with_noise = encrypted_message_with_noise[6:]
                # 去除噪声
                encrypted_message = remove_noise(encrypted_message_with_noise)
                # 使用binascii.hexlify转换为十六进制字符串并打印
                print("去除噪声后的加密消息(hex)：", binascii.hexlify(encrypted_message).decode())
            else:
                encrypted_message = encrypted_message_with_noise

            # 判断加密算法
            if encrypted_message.startswith(b"SM4:"):
                decrypted_message = sm4_decrypt(k_a, encrypted_message[4:])
            elif encrypted_message.startswith(b"AES:"):
                decrypted_message = aes_decrypt(k_a, encrypted_message[4:])
            else:
                print("收到未知格式的加密消息,无法解密")
                continue

            print("解密后的消息：", decrypted_message)