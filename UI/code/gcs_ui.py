from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget
from PyQt6.QtGui import QIcon
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
from PyQt6.QtCore import QThread, pyqtSignal
import hashlib
import base64

# sm2密钥协商
id_b = "42494C4C343536405941484F4F2E434F4D"
entl_b = "0088"

curve = sm2.Curve()

user_b = sm2.Sm2KeyAgreement(curve, id_b, entl_b)

p_b = user_b.curve.dot_to_bytes(user_b.pre_pub_key)
r_b = user_b.curve.dot_to_bytes(user_b.tem_pub_key)
z_b = user_b.id_auth_code

# socket绑定的ip
server_address = ('0.0.0.0', 38806)
uav_list = []
para1 = ''
para2 = ''


class ClientHandlerThread(QtCore.QThread):
    """
    自定义 QThread 线程类，用于处理与单个客户端的连接。
    """
    data_received = QtCore.pyqtSignal(str)  # 定义信号，用于将数据传递给 `ServerThread`

    def __init__(self, client_socket, client_address):
        super().__init__()
        self.client_socket = client_socket
        self.client_address = client_address

    def run(self):
        """
        线程执行的操作。
        """
        try:
            while True:
                # 接收来自客户端的数据
                data = self.client_socket.recv(1024).decode()
                if not data:
                    print(f"Connection closed by client {self.client_address}")
                    break

                print(f"Received from {self.client_address}: {data}")

                # 发出信号，将接收到的数据发送给 `ServerThread`
                self.data_received.emit(data)

        except Exception as e:
            print(f"Error handling connection from {self.client_address}: {e}")
        finally:
            # 关闭客户端连接
            self.client_socket.close()

    def send_data_to_client(self, data):
        try:
            # 发送数据到客户端
            self.client_socket.send(data.encode())
        except Exception as e:
            print(f"Error sending data to client {self.client_address}: {e}")



class ServerThread(QtCore.QThread):
    """
    自定义 QThread 线程类，用于运行服务器。
    """
    update_combo_signal = QtCore.pyqtSignal(str)  # 定义信号，用于更新 `QComboBox`

    def __init__(self):
        super().__init__()
        self.server_address = ('0.0.0.0', 38806)  # 服务器监听的地址和端口
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(self.server_address)
        self.server_socket.listen()
        self.client_threads = []

    def run(self):
        print("Server listening for client connections...")
        while True:
            # 等待客户端连接
            client_socket, client_address = self.server_socket.accept()
            print(f"Connected to client at {client_address}")

            # 创建一个新的 `ClientHandlerThread` 来处理客户端连接
            client_thread = ClientHandlerThread(client_socket, client_address)

            self.client_threads.append(client_thread)


            # 将 `ClientHandlerThread` 的 `data_received` 信号连接到 `ServerThread` 的 `update_combo_signal` 信号
            client_thread.data_received.connect(self.update_combo_signal)

            # 启动 `ClientHandlerThread`
            client_thread.start()

    def get_client_thread(self, index):
        return self.client_threads[index]



class Ui_MainWindow(object):
    def __init__(self):
        self.radioGroup2 = None
        self.radioGroup1 = None
        self.server_thread = None
        self.comboBox = None

        # 创建登录对话框
        self.login_dialog = QtWidgets.QDialog()
        self.login_dialog.setWindowTitle("登录")
        self.login_dialog.resize(400, 200)

        layout = QtWidgets.QVBoxLayout()

        # 创建密码输入框
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.password_edit.setMinimumHeight(40)  # 设置密码输入框的最小高度为 40

        layout.addWidget(QtWidgets.QLabel("请输入密码:"))
        layout.addWidget(self.password_edit)
        layout.addStretch()  # 添加一个伸缩因子,使密码输入框位于对话框的上半部分

        # 创建确认和取消按钮
        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.login_dialog.accept)
        buttons.rejected.connect(self.login_dialog.reject)
        layout.addWidget(buttons)

        self.login_dialog.setLayout(layout)


    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(589, 565)
        font = QtGui.QFont()
        font.setFamily("Roboto")
        font.setPointSize(14)
        MainWindow.setFont(font)
        icon=QIcon("tu.ico")
        MainWindow.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(parent=MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayoutWidget = QtWidgets.QWidget(parent=self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(20, 30, 160, 511))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label_4 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.verticalLayout.addWidget(self.label_4)
        self.label_3 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_3.setObjectName("label_3")
        self.verticalLayout.addWidget(self.label_3)
        self.label_2 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.label = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.label_5 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        self.label_5.setText("")
        self.label_5.setObjectName("label_5")
        self.verticalLayout.addWidget(self.label_5)
        self.label_8 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label_8.setFont(font)
        self.label_8.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_8.setObjectName("label_8")
        self.verticalLayout.addWidget(self.label_8)
        self.label_7 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.label_7.setFont(font)
        self.label_7.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.verticalLayout.addWidget(self.label_7)
        self.label_6 = QtWidgets.QLabel(parent=self.verticalLayoutWidget)
        self.label_6.setText("")
        self.label_6.setObjectName("label_6")
        self.verticalLayout.addWidget(self.label_6)
        self.comboBox = QtWidgets.QComboBox(parent=self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(210, 50, 161, 22))
        self.comboBox.setObjectName("comboBox")

        # 创建两个 QButtonGroup
        self.radioGroup1 = QtWidgets.QButtonGroup(self.centralwidget)
        self.radioGroup2 = QtWidgets.QButtonGroup(self.centralwidget)

        self.radioButton = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton.setGeometry(QtCore.QRect(210, 110, 95, 20))
        self.radioButton.setObjectName("radioButton")
        self.radioGroup1.addButton(self.radioButton)
        self.radioButton_2 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_2.setGeometry(QtCore.QRect(440, 110, 95, 20))
        self.radioButton_2.setObjectName("radioButton_2")
        self.radioGroup1.addButton(self.radioButton_2)
        self.lineEdit = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(210, 180, 113, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.radioButton_3 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_3.setGeometry(QtCore.QRect(210, 240, 95, 20))
        self.radioButton_3.setObjectName("radioButton_3")
        self.radioGroup2.addButton(self.radioButton_3)
        self.radioButton_4 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_4.setGeometry(QtCore.QRect(440, 240, 95, 20))
        self.radioButton_4.setObjectName("radioButton_4")
        self.radioGroup2.addButton(self.radioButton_4)
        self.radioButton_5 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_5.setGeometry(QtCore.QRect(210, 300, 95, 20))
        self.radioButton_5.setObjectName("radioButton_5")
        self.radioGroup2.addButton(self.radioButton_5)
        self.radioButton_6 = QtWidgets.QRadioButton(parent=self.centralwidget)
        self.radioButton_6.setGeometry(QtCore.QRect(440, 300, 95, 20))
        self.radioButton_6.setObjectName("radioButton_6")
        self.radioGroup2.addButton(self.radioButton_6)
        self.lineEdit_2 = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(210, 370, 113, 21))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.lineEdit_3 = QtWidgets.QLineEdit(parent=self.centralwidget)
        self.lineEdit_3.setGeometry(QtCore.QRect(210, 439, 113, 21))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.pushButton=QtWidgets.QPushButton(parent=self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(400,430,61,61))
        font = QtGui.QFont()
        font.setPointSize(14)
        font.setBold(False)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        label_font = QtGui.QFont(font)
        label_font.setBold(True)  # 使标签文本加粗
        for label in [self.label_4, self.label_3, self.label_2, self.label, self.label_8, self.label_7,self.radioButton,self.radioButton_2,self.radioButton_3,self.radioButton_4,self.radioButton_5,self.radioButton_6,self.pushButton]:
            label.setFont(label_font)

        # self.pushButton_2 = QtWidgets.QPushButton(parent=self.centralwidget)
        # self.pushButton_2.setGeometry(QtCore.QRect(210, 500, 121, 31))
        # self.pushButton_2.setObjectName("pushButton_2")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(parent=MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.pushButton.clicked.connect(self.on_button_click)

        # 创建并启动 `ServerThread`
        self.server_thread = ServerThread()
        self.server_thread.update_combo_signal.connect(self.update_combo_box)
        self.server_thread.start()

        def loadStyleSheet(filename):
            """加载外部QSS文件"""
            with open('UI/Qt/styles.qss', 'r',encoding='utf-8') as file:
                return file.read()
        # 加载外部样式文件并应用
        stylesheet = loadStyleSheet('styles.qss')
        MainWindow.setStyleSheet(stylesheet)
        # 设置槽函数
        self.radioGroup1.buttonClicked.connect(self.on_radio_button_group1_clicked)
        self.radioGroup2.buttonClicked.connect(self.on_radio_button_group2_clicked)
        def hash256(data):
            """
            计算给定数据的SHA-256哈希值。
            """
            if isinstance(data, str):
                # 如果是字符串,则编码为字节字符串
                data = data.encode('utf-8')

            sha256 = hashlib.sha256()
            sha256.update(data)
            return sha256.hexdigest()

        while True:
            if self.login_dialog.exec() == QtWidgets.QDialog.DialogCode.Rejected:
                sys.exit(app.exec())
            else:
                password = self.password_edit.text()
                if hash256(password) != "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3":
                    QtWidgets.QMessageBox.warning(MainWindow, "错误", "密码不正确,请重新输入")
                    self.password_edit.clear()  # 清空密码输入框
                else:
                    # 密码正确,显示主窗口
                    MainWindow.show()
                    break

    def update_combo_box(self, data):
        self.comboBox.addItem(data)

    def on_radio_button_group1_clicked(self, button):
        global para1
        """
        处理第一个 QButtonGroup 中的按钮点击事件。
        """
        # print(f"Group 1 selected: {button.text()}")
        para1 = button.text()


    def on_radio_button_group2_clicked(self, button):
        global para2
        """
        处理第二个 QButtonGroup 中的按钮点击事件。
        """
        para2 = button.text()


    #发送按钮执行的代码逻辑
    def on_button_click(self):

        #SM4加密函数
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

        #生成噪声字符串
        def inject_noise(ciphertext, noise_freq):
            noise_data = ""
            for i, char in enumerate(ciphertext):
                noise_data += char
                if (i + 1) % noise_freq == 0:
                    noise = random.choice(string.printable)
                    noise_data += noise
            noise_data += str(noise_freq)
            return noise_data

        #发送的明文
        data = self.lineEdit_3.text()
        #加密算法单选值
        print(para1)
        #发送方式单选值
        print(para2)

        # 通过加密方法转换明文
        if(para1=='AES'):
            data = aes_encrypt('97c11c6f2eeb6814fb006d114e7b8bfd', data)
            data = base64.b64encode(data)
            data = str(data, encoding='utf-8')
            data = '1' + data

        if(para1=='SM4'):
            data = sm4_encrypt('97c11c6f2eeb6814fb006d114e7b8bfd', data)
            data = base64.b64encode(data)
            data = str(data, encoding='utf-8')
            data = '2' + data

        #加入噪声方式
        if(para2=="真实发送"):
            data=inject_noise(data,5)
            data='is'+data

        # 获取选择的客户端地址
        current_index = self.comboBox.currentIndex()

        # 查找相应的客户端线程
        client_thread = self.server_thread.get_client_thread(current_index)

        bytes_data = '5646546'.encode('utf-8')

        # 如果客户端线程存在，则发送数据
        if client_thread:
            client_thread.send_data_to_client(data)
        else:
            print(f"没有找到客户端线程 {selected_client_address}")


    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "GCS控制面板"))
        self.label_4.setText(_translate("MainWindow", "无 人 机："))
        self.label_3.setText(_translate("MainWindow", "加密算法："))
        self.label_2.setText(_translate("MainWindow", "噪声频率："))
        self.label.setText(_translate("MainWindow", "发送噪声方式："))
        self.label_8.setText(_translate("MainWindow", "间隔(秒)："))
        self.label_7.setText(_translate("MainWindow", "发送消息："))
        self.radioButton.setText(_translate("MainWindow", "SM4"))
        self.radioButton_2.setText(_translate("MainWindow", "AES"))
        self.radioButton_3.setText(_translate("MainWindow", "定时发送"))
        self.radioButton_4.setText(_translate("MainWindow", "真实发送"))
        self.radioButton_5.setText(_translate("MainWindow", "两者都有"))
        self.radioButton_6.setText(_translate("MainWindow", "两者都无"))
        self.pushButton.setText(_translate("MainWindow", "发送"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec())

