# nacos_derby_rce_custom_memshell
>Warning
>
>**本工具仅供安全研究和学习使用。使用者需自行承担因使用此工具产生的所有法律及相关责任。请确保你的行为符合当地的法律和规定。作者不承担任何责任。如不接受，请勿使用此工具。**

Nacos Derby命令执行漏洞利用脚本，在原工具https://github.com/Wileysec/nacos_derby_rce
的基础上进行了修改，支持打入 jMG 生成的内存马

注意：-c/--memclass 参数值是jMG生成的内存马的注入器类名而不是内存马类名，如下图红框中的com.fasterxml.jackson.ek.ThreadUtil
![image](https://github.com/user-attachments/assets/b64b60d5-4ded-46cb-a24d-e34c7581c86c)
