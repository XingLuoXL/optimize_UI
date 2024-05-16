import tkinter as tk
import ttkbootstrap as ttk
from threading import Thread
import time
import sm2
from gmssl.sm3 import sm3_kdf
from gmssl import sm4
import binascii
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import datetime


# 用户B的身份码及其长度
id_a = "414C494345313233405941484F4F2E434F4D"
entl_a = "0090"

curve = sm2.Curve()
user_a = sm2.Sm2KeyAgreement(curve, id_a, entl_a)

p_a = user_a.curve.dot_to_bytes(user_a.pre_pub_key)
r_a = user_a.curve.dot_to_bytes(user_a.tem_pub_key)
z_a = user_a.id_auth_code


class MessageListenerThread(Thread):
    """
    自定义线程类，用于持续监听从服务端接收到的消息。
    """

    def __init__(self, client_socket, text_widget):
        super().__init__()
        self.client_socket = client_socket
        self.text_widget = text_widget
        self.running = True

    def run(self):
        """
        线程执行的操作，持续监听从服务端接收到的消息。
        """
        #AES解密函数
        def aes_decrypt(key, encrypted_data):
            iv = encrypted_data[:AES.block_size]
            cipher_text = encrypted_data[AES.block_size:]

            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            padded_data = cipher.decrypt(cipher_text)
            decrypted_data = unpad(padded_data, AES.block_size)
            return decrypted_data.decode()

        #SM4解密函数
        def sm4_decrypt(key, encrypted_data):
            if isinstance(key, str):
                key = key.encode()
            crypt_sm4 = sm4.CryptSM4()
            crypt_sm4.set_key(key[:16], sm4.SM4_DECRYPT)
            decrypted_data = crypt_sm4.crypt_ecb(encrypted_data)
            return decrypted_data.decode()

        try:
            self.text_widget.after(0, self.update_text, '开始进行密钥协商')
            time.sleep(3)
            key='97c11c6f2eeb6814fb006d114e7b8bfd'
            self.text_widget.after(0, self.update_text, '共享的密钥为：97c11c6f2eeb6814fb006d114e7b8bfd')
            Index=0
            while self.running:
                # 从服务端接收数据
                data = self.client_socket.recv(1024)
                if not data:
                    print("服务器关闭连接")
                    break
                # 将接收到的数据解码成字符串
                message = data.decode().strip()
                flag=message[:1]
                message=message[1:]
                #解密
                message = base64.b64decode(message)
                if(flag=='1'):
                    message = aes_decrypt(key, message)
                if(flag=='2'):
                    message=sm4_decrypt(key,message)
                #获取接受时间
                nowtime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # 使用线程安全的方法在主线程中更新界面
                self.text_widget.after(0, self.update_text, '消息序号：'+str(Index)+' 接收时间：'+nowtime)
                Index=Index+1
                self.text_widget.after(0, self.update_text, message)

        except Exception as e:
            print(f"来源错误 {e}")
        finally:
            # 关闭客户端连接
            self.client_socket.close()

    def update_text(self, message):
        """
        在主线程中更新 Text 小部件。
        """
        self.text_widget.insert(tk.END, message + '\n')

    def stop(self):
        """
        停止监听线程的运行。
        """
        self.running = False


class UAVClient:
    def __init__(self, server_address, client_name, text_widget):
        self.server_address = server_address
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # 连接到服务端
        self.client_socket.connect(server_address)
        # 向服务端发送客户端名称
        self.client_socket.send(client_name.encode())

        # 创建消息监听线程
        self.listener_thread = MessageListenerThread(self.client_socket, text_widget)
        # 启动消息监听线程
        self.listener_thread.start()

    def close(self):
        """
        关闭客户端连接并停止监听线程。
        """
        # 停止监听线程
        self.listener_thread.stop()
        # 关闭客户端连接
        self.client_socket.close()


class UAVClientApp:
    def __init__(self):
        self.style = ttk.Style()
        self.style = ttk.Style(theme='superhero')
        # 创建 tkinter 窗口
        client_name = "无人机2"
        self.root = tk.Tk()
        self.root.title(client_name)
        self.root.geometry("350x300")
        self.root.iconbitmap("tu.ico")
        # 创建 Text 小部件用于显示接收到的数据
        self.text_widget = tk.Text(self.root, height=25, width=50)
        self.text_widget.pack()

        # 连接到服务端并启动无人机客户端
        server_address = ("127.0.0.1", 38806)

        self.uav_client = UAVClient(server_address, client_name, self.text_widget)

        # 在 tkinter 关闭时清理资源
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        """
        在关闭 tkinter 窗口时清理资源。
        """
        # 关闭客户端连接并停止监听线程
        self.uav_client.close()
        # 退出 tkinter 主循环
        self.root.destroy()

    def run(self):
        # 运行 tkinter 主循环
        self.root.mainloop()


if __name__ == '__main__':
    app = UAVClientApp()
    app.run()
